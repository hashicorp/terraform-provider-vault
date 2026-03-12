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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
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

var _ resource.Resource = &KeyResource{}
var _ resource.ResourceWithImportState = &KeyResource{}

type KeyResource struct {
	base.ResourceWithConfigure
}

type KeyResourceModel struct {
	base.BaseModel

	Mount             types.String `tfsdk:"mount"`
	Name              types.String `tfsdk:"name"`
	Type              types.String `tfsdk:"type"`
	DeletionAllowed   types.Bool   `tfsdk:"deletion_allowed"`
	ReplicaRegions    types.Set    `tfsdk:"replica_regions"`
	LatestVersion     types.Int64  `tfsdk:"latest_version"`
	MinEnabledVersion types.Int64  `tfsdk:"min_enabled_version"`
}

func NewKeyResource() resource.Resource {
	return &KeyResource{}
}

func (r *KeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keymgmt_key"
}

func (r *KeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Key Management key in Vault",

		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Path of the Key Management secrets engine mount. Must match the `path` of a `vault_mount` " +
					"resource with `type = \"keymgmt\"`. Use `vault_mount.keymgmt.path` here.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Specifies the name of the key to create.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldType: schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("rsa-2048"),
				MarkdownDescription: "Specifies the type of cryptographic key to create. aes256-gcm96, rsa-2048, rsa-3072, rsa-4096, " +
					"ecdsa-p256, ecdsa-p384, ecdsa-p521 key types are supported. Defaults to `rsa-2048`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldDeletionAllowed: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Specifies if the key is allowed to be deleted.",
			},
			consts.FieldReplicaRegions: schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Specifies the regions in which the key should be replicated. Supported only for AWS KMS.",
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldLatestVersion: schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Specifies the latest version of the key.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldMinEnabledVersion: schema.Int64Attribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Specifies the minimum enabled version of the key. All versions of the key less than the specified version " +
					"will be disabled for cryptographic operations in the KMS provider that the key has been distributed to. " +
					"Setting this value to 0 means that all versions will be enabled.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *KeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KeyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	apiPath := data.APIPath()

	writeData := map[string]interface{}{
		"type": data.Type.ValueString(),
	}

	if !data.ReplicaRegions.IsNull() {
		var regions []string
		resp.Diagnostics.Append(data.ReplicaRegions.ElementsAs(ctx, &regions, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(regions) > 0 {
			writeData[consts.FieldReplicaRegions] = regions
		}
	}

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError(ErrCreating(ResourceTypeKey, apiPath, err))
		return
	}

	// Update deletion_allowed configuration only when it differs from the default.
	if data.DeletionAllowed.ValueBool() {
		configData := map[string]interface{}{
			consts.FieldDeletionAllowed: true,
		}
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, configData); err != nil {
			resp.Diagnostics.AddError(ErrUpdating(ResourceTypeKeyConfig, apiPath, err))
			return
		}
	}

	// Read back the state from Vault
	responseData, exists := r.readKey(ctx, cli, apiPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		resp.Diagnostics.AddError(
			"Unexpected error after creating Key Management key",
			fmt.Sprintf("Key Management key not found at path %q immediately after creation", apiPath),
		)
		return
	}

	data.parseKeyResponse(ctx, responseData)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	apiPath := data.APIPath()
	responseData, exists := r.readKey(ctx, cli, apiPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		tflog.Warn(ctx, "Key Management key not found, removing from state", map[string]interface{}{
			"path": apiPath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	data.parseKeyResponse(ctx, responseData)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state KeyResourceModel
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

	if !plan.DeletionAllowed.Equal(state.DeletionAllowed) {
		writeData[consts.FieldDeletionAllowed] = plan.DeletionAllowed.ValueBool()
	}

	if !plan.MinEnabledVersion.Equal(state.MinEnabledVersion) {
		writeData[consts.FieldMinEnabledVersion] = plan.MinEnabledVersion.ValueInt64()
	}

	if len(writeData) > 0 {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError(ErrUpdating(ResourceTypeKey, apiPath, err))
			return
		}
	}

	responseData, exists := r.readKey(ctx, cli, apiPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		resp.Diagnostics.AddError(
			"Unexpected error after updating Key Management key",
			fmt.Sprintf("Key Management key not found at path %q immediately after update", apiPath),
		)
		return
	}

	plan.parseKeyResponse(ctx, responseData)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *KeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KeyResourceModel
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
		resp.Diagnostics.AddError(ErrDeleting(ResourceTypeKey, apiPath, err))
		return
	}
}

func (r *KeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" {
		resp.Diagnostics.AddError(
			"Empty Import ID",
			"Import ID cannot be empty. Expected format: <mount>/key/<name>",
		)
		return
	}

	mount, name, err := ParseKeyPath(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Unable to parse import ID: %s\n\nExpected format: <mount>/key/<name>\nExample: keymgmt/key/my-key\n\nError: %s", req.ID, err.Error()),
		)
		return
	}

	if mount == "" || name == "" {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Import ID contains empty fields. Expected format: <mount>/key/<name>\nExample: keymgmt/key/my-key\n\nParsed mount: %q, name: %q", mount, name),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)

	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		tflog.Debug(ctx, fmt.Sprintf("Setting namespace from %s: %s", consts.EnvVarVaultNamespaceImport, ns))
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

// APIPath returns the Vault API path for this key.
func (m *KeyResourceModel) APIPath() string {
	return BuildKeyPath(m.Mount.ValueString(), m.Name.ValueString())
}

// getVaultClient returns a Vault client for the given namespace, adding a diagnostic on error.
func (r *KeyResource) getVaultClient(ctx context.Context, namespace string, diags *diag.Diagnostics) (*vaultapi.Client, bool) {
	cli, err := client.GetClient(ctx, r.Meta(), namespace)
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return nil, false
	}
	return cli, true
}

// readKey reads the key from Vault. Returns (data, true) if found, (nil, false) otherwise. API errors are added to diags.
func (r *KeyResource) readKey(ctx context.Context, cli *vaultapi.Client, apiPath string, diags *diag.Diagnostics) (map[string]interface{}, bool) {
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		diags.AddError(ErrReading(ResourceTypeKey, apiPath, err))
		return nil, false
	}
	if vaultResp == nil {
		return nil, false
	}
	return vaultResp.Data, true
}

// parseKeyResponse parses the Vault API response data into the resource model
func (data *KeyResourceModel) parseKeyResponse(ctx context.Context, responseData map[string]interface{}) {
	if v, ok := responseData["type"].(string); ok {
		data.Type = types.StringValue(v)
	}
	if v, ok := responseData[consts.FieldDeletionAllowed].(bool); ok {
		data.DeletionAllowed = types.BoolValue(v)
	}

	if v, ok := responseData[consts.FieldLatestVersion]; ok {
		data.LatestVersion = SetInt64FromInterface(v)
	}

	if v, ok := responseData[consts.FieldMinEnabledVersion]; ok {
		data.MinEnabledVersion = SetInt64FromInterface(v)
	}

	if v, ok := responseData[consts.FieldReplicaRegions].([]interface{}); ok {
		regions := make([]string, 0, len(v))
		for _, r := range v {
			if s, ok := r.(string); ok {
				regions = append(regions, s)
			}
		}
		setValue, diagsResult := types.SetValueFrom(ctx, types.StringType, regions)
		if !diagsResult.HasError() {
			data.ReplicaRegions = setValue
		}
	}
}
