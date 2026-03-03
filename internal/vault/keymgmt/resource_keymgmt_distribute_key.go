// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ resource.Resource = &DistributeKeyResource{}
var _ resource.ResourceWithImportState = &DistributeKeyResource{}

type DistributeKeyResource struct {
	base.ResourceWithConfigure
}

type DistributeKeyResourceModel struct {
	base.BaseModel
	Path       types.String `tfsdk:"path"`
	KMSName    types.String `tfsdk:"kms_name"`
	KeyName    types.String `tfsdk:"key_name"`
	Purpose    types.Set    `tfsdk:"purpose"`
	Protection types.String `tfsdk:"protection"`
	KeyID      types.String `tfsdk:"key_id"`
	Versions   types.List   `tfsdk:"versions"`
}

func NewDistributeKeyResource() resource.Resource {
	return &DistributeKeyResource{}
}

func (r *DistributeKeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keymgmt_distribute_key"
}

func (r *DistributeKeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Distributes a Key Management key to a KMS provider",

		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Path where the Key Management secrets engine is mounted",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKMSName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the KMS provider",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeyName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the key to distribute",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldPurpose: schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Purposes for which the key can be used (e.g., encrypt, decrypt, sign, verify)",
			},
			consts.FieldProtection: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Protection level for the key (e.g., hsm, software)",
			},
			consts.FieldKeyID: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the key in the KMS provider",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldVersions: schema.ListAttribute{
				Computed:            true,
				ElementType:         types.Int64Type,
				MarkdownDescription: "Versions of the key distributed to the KMS provider",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *DistributeKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DistributeKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := data.Path.ValueString()
	kmsName := data.KMSName.ValueString()
	keyName := data.KeyName.ValueString()
	apiPath := buildDistributeKeyPath(vaultPath, kmsName, keyName)

	writeData := map[string]interface{}{}

	var purposes []string
	resp.Diagnostics.Append(data.Purpose.ElementsAs(ctx, &purposes, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	writeData["purpose"] = purposes

	if !data.Protection.IsNull() {
		writeData["protection"] = data.Protection.ValueString()
	}

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError(errCreating("Key Management key distribution", apiPath, err))
		return
	}

	r.read(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DistributeKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DistributeKeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.read(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if resource still exists by verifying computed fields were populated
	if data.KeyID.IsNull() {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DistributeKeyResource) read(ctx context.Context, cli *api.Client, data *DistributeKeyResourceModel, diags *diag.Diagnostics) {
	// Build API path from data fields
	apiPath := buildDistributeKeyPath(data.Path.ValueString(), data.KMSName.ValueString(), data.KeyName.ValueString())
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		diags.AddError(errReading("Key Management key distribution", apiPath, err))
		return
	}

	if vaultResp == nil {
		// Resource has been deleted outside Terraform
		return
	}

	if v, ok := vaultResp.Data["purpose"].([]interface{}); ok {
		purposes, d := types.SetValueFrom(ctx, types.StringType, v)
		diags.Append(d...)
		if !diags.HasError() {
			data.Purpose = purposes
		}
	}
	if v, ok := vaultResp.Data["protection"].(string); ok {
		data.Protection = types.StringValue(v)
	}

	// Always set key_id and versions to ensure they are known after apply
	data.KeyID = setStringFromInterface(vaultResp.Data["key_id"])

	if v, ok := vaultResp.Data["versions"].([]interface{}); ok && len(v) > 0 {
		versions, d := types.ListValueFrom(ctx, types.Int64Type, v)
		diags.Append(d...)
		if !diags.HasError() {
			data.Versions = versions
		}
	} else {
		// Set to empty list instead of leaving unknown
		emptyList, d := types.ListValueFrom(ctx, types.Int64Type, []int64{})
		diags.Append(d...)
		if !diags.HasError() {
			data.Versions = emptyList
		}
	}
}

func (r *DistributeKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state DistributeKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Build API path from fields
	apiPath := buildDistributeKeyPath(plan.Path.ValueString(), plan.KMSName.ValueString(), plan.KeyName.ValueString())
	writeData := map[string]interface{}{}
	hasChanges := false

	if !plan.Purpose.Equal(state.Purpose) {
		var purposes []string
		resp.Diagnostics.Append(plan.Purpose.ElementsAs(ctx, &purposes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		writeData["purpose"] = purposes
		hasChanges = true
	}
	if !plan.Protection.Equal(state.Protection) {
		if !plan.Protection.IsNull() && !plan.Protection.IsUnknown() {
			writeData["protection"] = plan.Protection.ValueString()
			hasChanges = true
		}
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError(errUpdating("Key Management key distribution", apiPath, err))
			return
		}
	}

	r.read(ctx, cli, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DistributeKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data DistributeKeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Build API path from fields
	apiPath := buildDistributeKeyPath(data.Path.ValueString(), data.KMSName.ValueString(), data.KeyName.ValueString())
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError(errDeleting("Key Management key distribution", apiPath, err))
		return
	}
}

func (r *DistributeKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Validate import ID is not empty
	if req.ID == "" {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			"Import identifier cannot be empty. Expected format: '<mount_path>/kms/<kms_name>/key/<key_name>', "+
				"namespace can be specified using the env var "+consts.EnvVarVaultNamespaceImport,
		)
		return
	}

	// Parse the import ID to extract path, kms_name, key_name
	mountPath, kmsName, keyName, err := parseDistributeKeyPath(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s. Expected format: '<mount_path>/kms/<kms_name>/key/<key_name>', "+
				"namespace can be specified using the env var %s", req.ID, err.Error(), consts.EnvVarVaultNamespaceImport),
		)
		return
	}

	// Set the individual fields in state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldPath), mountPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldKMSName), kmsName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldKeyName), keyName)...)

	// Handle namespace if needed
	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(
			resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}
