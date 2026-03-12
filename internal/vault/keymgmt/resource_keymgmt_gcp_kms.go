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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	vaultapi "github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ resource.Resource = &GCPKMSResource{}
var _ resource.ResourceWithImportState = &GCPKMSResource{}

type GCPKMSResource struct {
	base.ResourceWithConfigure
}

type GCPKMSResourceModel struct {
	base.BaseModel
	Mount                types.String `tfsdk:"mount"`
	Name                 types.String `tfsdk:"name"`
	KeyCollection        types.String `tfsdk:"key_collection"`
	CredentialsWO        types.Map    `tfsdk:"credentials_wo"`
	CredentialsWOVersion types.Int64  `tfsdk:"credentials_wo_version"`
}

func NewGCPKMSResource() resource.Resource {
	return &GCPKMSResource{}
}

func (r *GCPKMSResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keymgmt_gcp_kms"
}

func (r *GCPKMSResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a GCP Cloud KMS provider for Vault Key Management",

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
				MarkdownDescription: "Specifies the name of the GCP Cloud KMS provider. Cannot be changed after creation.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeyCollection: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Refers to a location to store keys in the GCP Cloud KMS provider. Cannot be changed after creation.",
			},
			consts.FieldCredentialsWO: schema.MapAttribute{
				Required:    true,
				Sensitive:   true,
				WriteOnly:   true,
				ElementType: types.StringType,
				MarkdownDescription: "The credentials to use for authentication with the GCP Cloud KMS provider. Supplying values for this parameter " +
					"is optional, as credentials may also be specified as environment variables.",
			},
			consts.FieldCredentialsWOVersion: schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Version number for the write-only credentials. Increment this value to trigger a credential rotation. " +
					"Changing this value will cause the credentials to be re-sent to Vault during the next apply.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *GCPKMSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GCPKMSResourceModel
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
		"provider":       ProviderGCPCKMS,
		"key_collection": data.KeyCollection.ValueString(),
	}

	// Read write-only credentials from Config (the only place write-only values are accessible)
	var configModel GCPKMSResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &configModel)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.CredentialsWO = configModel.CredentialsWO

	if !data.CredentialsWO.IsNull() && !data.CredentialsWO.IsUnknown() {
		var creds map[string]string
		resp.Diagnostics.Append(data.CredentialsWO.ElementsAs(ctx, &creds, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		writeData["credentials"] = creds
	}

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError(ErrCreating(ResourceTypeGCPCKMS, apiPath, err))
		return
	}

	// Read back the state from Vault
	responseData, exists := r.readKMS(ctx, cli, apiPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		resp.Diagnostics.AddError(
			"Unexpected error after creating GCP Cloud KMS provider",
			fmt.Sprintf("GCP Cloud KMS provider not found at path %q immediately after creation", apiPath),
		)
		return
	}

	// Parse response data
	data.parseGCPKMSResponse(responseData)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GCPKMSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GCPKMSResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	// Build API path and read from Vault
	apiPath := data.APIPath()
	responseData, exists := r.readKMS(ctx, cli, apiPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		tflog.Warn(ctx, "GCP Cloud KMS provider not found, removing from state", map[string]interface{}{
			"path": apiPath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// Parse response data
	data.parseGCPKMSResponse(responseData)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GCPKMSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state GCPKMSResourceModel
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
	writeData := map[string]interface{}{
		"provider": ProviderGCPCKMS,
	}
	hasChanges := false

	if !plan.KeyCollection.Equal(state.KeyCollection) {
		writeData["key_collection"] = plan.KeyCollection.ValueString()
		hasChanges = true
	}

	if !plan.CredentialsWOVersion.Equal(state.CredentialsWOVersion) {
		// Read write-only credentials from Config (the only place write-only values are accessible)
		var configModel GCPKMSResourceModel
		resp.Diagnostics.Append(req.Config.Get(ctx, &configModel)...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.CredentialsWO = configModel.CredentialsWO

		if !plan.CredentialsWO.IsNull() && !plan.CredentialsWO.IsUnknown() {
			var creds map[string]string
			resp.Diagnostics.Append(plan.CredentialsWO.ElementsAs(ctx, &creds, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
			writeData["credentials"] = creds
		}
		hasChanges = true
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError(ErrUpdating(ResourceTypeGCPCKMS, apiPath, err))
			return
		}
	}

	// Read back the state from Vault
	responseData, exists := r.readKMS(ctx, cli, apiPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		resp.Diagnostics.AddError(
			"Unexpected error after updating GCP Cloud KMS provider",
			fmt.Sprintf("GCP Cloud KMS provider not found at path %q immediately after update", apiPath),
		)
		return
	}

	// Parse response data
	plan.parseGCPKMSResponse(responseData)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *GCPKMSResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GCPKMSResourceModel
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
		resp.Diagnostics.AddError(ErrDeleting(ResourceTypeGCPCKMS, apiPath, err))
		return
	}
}

func (r *GCPKMSResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Validate import ID is not empty
	if req.ID == "" {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			"Import identifier cannot be empty. Expected format: '<mount_path>/kms/<name>', "+
				"namespace can be specified using the env var "+consts.EnvVarVaultNamespaceImport,
		)
		return
	}

	// Parse the import ID to extract path and name
	mountPath, kmsName, err := ParseKMSPath(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s. Expected format: '<mount_path>/kms/<name>', "+
				"namespace can be specified using the env var %s", req.ID, err.Error(), consts.EnvVarVaultNamespaceImport),
		)
		return
	}

	// Set the individual fields in state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mountPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), kmsName)...)

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

// APIPath returns the Vault API path for this KMS provider.
func (m *GCPKMSResourceModel) APIPath() string {
	return BuildKMSPath(m.Mount.ValueString(), m.Name.ValueString())
}

// getVaultClient returns a Vault client for the given namespace, adding a diagnostic on error.
func (r *GCPKMSResource) getVaultClient(ctx context.Context, namespace string, diags *diag.Diagnostics) (*vaultapi.Client, bool) {
	cli, err := client.GetClient(ctx, r.Meta(), namespace)
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return nil, false
	}
	return cli, true
}

// readKMS reads the KMS provider from Vault. Returns (data, true) if found, (nil, false) otherwise. API errors are added to diags.
func (r *GCPKMSResource) readKMS(ctx context.Context, cli *vaultapi.Client, apiPath string, diags *diag.Diagnostics) (map[string]interface{}, bool) {
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		diags.AddError(ErrReading(ResourceTypeGCPCKMS, apiPath, err))
		return nil, false
	}
	if vaultResp == nil {
		return nil, false
	}
	return vaultResp.Data, true
}

func (data *GCPKMSResourceModel) parseGCPKMSResponse(responseData map[string]interface{}) {
	if v, ok := responseData["key_collection"].(string); ok {
		data.KeyCollection = types.StringValue(v)
	}
}
