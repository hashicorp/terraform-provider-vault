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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	vaultapi "github.com/hashicorp/vault/api"

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
	Mount      types.String `tfsdk:"mount"`
	KMSName    types.String `tfsdk:"kms_name"`
	KeyName    types.String `tfsdk:"key_name"`
	Purpose    types.Set    `tfsdk:"purpose"`
	Protection types.String `tfsdk:"protection"`
	Versions   types.Map    `tfsdk:"versions"`
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
			consts.FieldMount: schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Path of the Key Management secrets engine mount. Must match the `path` of a `vault_mount` " +
					"resource with `type = \"keymgmt\"`. Use `vault_mount.keymgmt.path` here.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKMSName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Specifies the name of the KMS provider to distribute the given key to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeyName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Specifies the name of the key to distribute to the given KMS provider.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldPurpose: schema.SetAttribute{
				Required:    true,
				ElementType: types.StringType,
				MarkdownDescription: "Specifies the purpose of the key. The purpose defines a set of cryptographic capabilities that " +
					"the key will have in the KMS provider. A key must have at least one of the supported purposes. " +
					"The following values are supported : encrypt, decrypt, sign, verify, wrap, unwrap.",
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldProtection: schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("hsm"),
				MarkdownDescription: "Specifies the protection of the key. The protection defines where cryptographic operations are " +
					"performed with the key in the KMS provider. The following values are supported: hsm, software. Defaults to `hsm`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldVersions: schema.MapAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Map of distributed key versions to their identifiers in the KMS provider.",
				PlanModifiers: []planmodifier.Map{
					mapplanmodifier.UseStateForUnknown(),
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

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	apiPath := data.APIPath()
	writeData := map[string]interface{}{}

	var purposes []string
	resp.Diagnostics.Append(data.Purpose.ElementsAs(ctx, &purposes, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	writeData[consts.FieldPurpose] = purposes

	if !data.Protection.IsNull() {
		writeData[consts.FieldProtection] = data.Protection.ValueString()
	}

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError(ErrCreating(ResourceTypeKeyDistribution, apiPath, err))
		return
	}

	// Read back the state from Vault
	responseData, exists := r.readDistributeKey(ctx, cli, apiPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		resp.Diagnostics.AddError(
			"Unexpected error after creating key distribution",
			fmt.Sprintf("Key distribution not found at path %q immediately after creation", apiPath),
		)
		return
	}

	data.parseDistributeKeyResponse(ctx, responseData, &resp.Diagnostics)
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

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	apiPath := data.APIPath()
	responseData, exists := r.readDistributeKey(ctx, cli, apiPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		tflog.Warn(ctx, "key distribution not found, removing from state", map[string]interface{}{
			consts.FieldPath: apiPath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// Parse response data
	data.parseDistributeKeyResponse(ctx, responseData, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DistributeKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state DistributeKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, ok := r.getVaultClient(ctx, plan.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	apiPath := plan.APIPath()
	writeData := map[string]interface{}{}
	hasChanges := false

	if !plan.Purpose.Equal(state.Purpose) {
		var purposes []string
		resp.Diagnostics.Append(plan.Purpose.ElementsAs(ctx, &purposes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		writeData[consts.FieldPurpose] = purposes
		hasChanges = true
	}
	if !plan.Protection.Equal(state.Protection) {
		if !plan.Protection.IsNull() && !plan.Protection.IsUnknown() {
			writeData[consts.FieldProtection] = plan.Protection.ValueString()
			hasChanges = true
		}
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError(ErrUpdating(ResourceTypeKeyDistribution, apiPath, err))
			return
		}
	}

	// Read back the state from Vault
	responseData, exists := r.readDistributeKey(ctx, cli, apiPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		resp.Diagnostics.AddError(
			"Unexpected error after updating key distribution",
			fmt.Sprintf("Key distribution not found at path %q immediately after update", apiPath),
		)
		return
	}

	plan.parseDistributeKeyResponse(ctx, responseData, &resp.Diagnostics)
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

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	apiPath := data.APIPath()
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError(ErrDeleting(ResourceTypeKeyDistribution, apiPath, err))
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
	mountPath, kmsName, keyName, err := ParseDistributeKeyPath(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s. Expected format: '<mount_path>/kms/<kms_name>/key/<key_name>', "+
				"namespace can be specified using the env var %s", req.ID, err.Error(), consts.EnvVarVaultNamespaceImport),
		)
		return
	}

	// Set the individual fields in state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mountPath)...)
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

// APIPath returns the Vault API path for this key distribution.
func (m *DistributeKeyResourceModel) APIPath() string {
	return BuildDistributeKeyPath(m.Mount.ValueString(), m.KMSName.ValueString(), m.KeyName.ValueString())
}

// getVaultClient returns a Vault client for the given namespace, adding a diagnostic on error.
func (r *DistributeKeyResource) getVaultClient(ctx context.Context, namespace string, diags *diag.Diagnostics) (*vaultapi.Client, bool) {
	cli, err := client.GetClient(ctx, r.Meta(), namespace)
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return nil, false
	}
	return cli, true
}

// readDistributeKey reads the key distribution from Vault. Returns (data, true) if found, (nil, false) otherwise. API errors are added to diags.
func (r *DistributeKeyResource) readDistributeKey(ctx context.Context, cli *vaultapi.Client, apiPath string, diags *diag.Diagnostics) (map[string]interface{}, bool) {
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		diags.AddError(ErrReading(ResourceTypeKeyDistribution, apiPath, err))
		return nil, false
	}
	if vaultResp == nil {
		return nil, false
	}
	return vaultResp.Data, true
}

// parseDistributeKeyResponse extracts data from Vault API response data into the distribute key model.
func (data *DistributeKeyResourceModel) parseDistributeKeyResponse(ctx context.Context, responseData map[string]interface{}, diags *diag.Diagnostics) {
	if v, ok := responseData[consts.FieldPurpose].([]interface{}); ok {
		purposes, d := types.SetValueFrom(ctx, types.StringType, v)
		diags.Append(d...)
		if !diags.HasError() {
			data.Purpose = purposes
		}
	}
	if v, ok := responseData[consts.FieldProtection].(string); ok {
		data.Protection = types.StringValue(v)
	}

	// versions is a map<string, string>: version number → key identifier
	if v, ok := responseData[consts.FieldVersions].(map[string]interface{}); ok {
		versions, d := types.MapValueFrom(ctx, types.StringType, v)
		diags.Append(d...)
		if !diags.HasError() {
			data.Versions = versions
		}
	} else if data.Versions.IsUnknown() {
		emptyMap, d := types.MapValueFrom(ctx, types.StringType, map[string]string{})
		diags.Append(d...)
		if !diags.HasError() {
			data.Versions = emptyMap
		}
	}
}
