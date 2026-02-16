// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
	base.WithImportByID
}

type DistributeKeyResourceModel struct {
	base.BaseModelLegacy
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
	base.MustAddLegacyBaseSchema(&resp.Schema)
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
		resp.Diagnostics.AddError("Error distributing Key Management key to KMS", fmt.Sprintf("Error distributing key at %s: %s", apiPath, err))
		return
	}

	data.ID = types.StringValue(apiPath)
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

	if data.ID.IsNull() {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DistributeKeyResource) read(ctx context.Context, cli *api.Client, data *DistributeKeyResourceModel, diags *diag.Diagnostics) {
	apiPath := data.ID.ValueString()
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		diags.AddError("Error reading Key Management key distribution", fmt.Sprintf("Error reading key distribution at %s: %s", apiPath, err))
		return
	}

	if vaultResp == nil {
		data.ID = types.StringNull()
		return
	}

	parts := strings.Split(strings.Trim(apiPath, "/"), "/")
	kmsIndex, keyIndex := -1, -1
	for i, part := range parts {
		if part == "kms" {
			kmsIndex = i
		} else if part == "key" && i > kmsIndex {
			keyIndex = i
		}
	}

	if kmsIndex == -1 || keyIndex == -1 || kmsIndex+1 >= len(parts) || keyIndex+1 >= len(parts) {
		diags.AddError("Invalid path structure", fmt.Sprintf("Invalid key distribution path: %s", apiPath))
		return
	}

	data.Path = types.StringValue(strings.Join(parts[:kmsIndex], "/"))
	data.KMSName = types.StringValue(parts[kmsIndex+1])
	data.KeyName = types.StringValue(parts[keyIndex+1])

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
	if v, ok := vaultResp.Data["key_id"].(string); ok && v != "" {
		data.KeyID = types.StringValue(v)
	} else {
		data.KeyID = types.StringValue("")
	}

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

	apiPath := plan.ID.ValueString()
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
		writeData["protection"] = plan.Protection.ValueString()
		hasChanges = true
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError("Error updating Key Management key distribution", fmt.Sprintf("Error updating key distribution at %s: %s", apiPath, err))
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

	apiPath := data.ID.ValueString()
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError("Error deleting Key Management key distribution", fmt.Sprintf("Error deleting key distribution at %s: %s", apiPath, err))
		return
	}
}

func buildDistributeKeyPath(mountPath, kmsName, keyName string) string {
	return strings.Trim(mountPath, "/") + "/kms/" + kmsName + "/key/" + keyName
}
