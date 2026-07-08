// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/mount"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &GCPKMSSecretBackendResource{}

// NewGCPKMSSecretBackendResource returns the implementation for this resource
func NewGCPKMSSecretBackendResource() resource.Resource {
	return &GCPKMSSecretBackendResource{}
}

// GCPKMSSecretBackendResource implements the methods that define this resource
type GCPKMSSecretBackendResource struct {
	base.ResourceWithConfigure
}

// GCPKMSSecretBackendModel describes the Terraform resource data model.
//
// This resource is self-managing: it creates and manages its own mount point
// in addition to configuring the GCP KMS secrets engine.
type GCPKMSSecretBackendModel struct {
	base.BaseModel

	// Mount configuration fields (path, type, ttls, audit keys, etc.)
	mount.MountModel

	// GCP KMS backend configuration
	CredentialsWO        types.String `tfsdk:"credentials_wo"`
	CredentialsWOVersion types.Int64  `tfsdk:"credentials_wo_version"`
	Scopes               types.Set    `tfsdk:"scopes"`

	// Computed
	ID types.String `tfsdk:"id"`
}

func (r *GCPKMSSecretBackendResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcpkms_secret_backend"
}

func (r *GCPKMSSecretBackendResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	// Start with backend-specific attributes
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a GCP KMS secrets engine mount in Vault. This resource creates and configures " +
			"the mount point and the GCP KMS backend in a single resource.",
		Attributes: map[string]schema.Attribute{
			// The mount type is fixed for this self-managing backend, so it is
			// computed rather than user-supplied. The shared mount schema defines
			// type as Required, so it is excluded below and redefined here.
			consts.FieldType: schema.StringAttribute{
				MarkdownDescription: "Type of the backend, such as 'gcpkms'",
				Computed:            true,
			},
			// GCP KMS backend-specific fields
			consts.FieldCredentialsWO: schema.StringAttribute{
				MarkdownDescription: "JSON-encoded GCP service account credentials. Write-only — never " +
					"stored in Terraform state. Leave this blank (`\"\"`) to use Default Application Credentials " +
					"or instance metadata authentication. Requires Terraform 1.11+.",
				Required:  true,
				Sensitive: true,
				WriteOnly: true,
			},
			consts.FieldCredentialsWOVersion: schema.Int64Attribute{
				MarkdownDescription: "Version number for the write-only credentials. Increment this value to trigger a credential rotation. " +
					"Changing this value will cause the credentials to be re-sent to Vault during the next apply.",
				Required: true,
			},
			consts.FieldScopes: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "OAuth scopes to use for GCP API requests. Defaults to ['https://www.googleapis.com/auth/cloudkms'].",
				Optional:            true,
				Computed:            true,
			},
			// Computed field
			consts.FieldID: schema.StringAttribute{
				MarkdownDescription: "ID of the mount. Used for ephemeral resource dependencies.",
				Computed:            true,
			},
		},
	}

	// Add mount configuration fields
	mount.MustAddMountSchema(&resp.Schema, consts.FieldType)

	// Add base schema fields (namespace, etc.)
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *GCPKMSSecretBackendResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GCPKMSSecretBackendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var configModel GCPKMSSecretBackendModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &configModel)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Copy the write-only credential value from Config into our data model.
	// This is the only way to access write-only field values.
	data.CredentialsWO = configModel.CredentialsWO

	tflog.Debug(ctx, "Create: credentials_wo from Config", map[string]any{
		"is_null":    data.CredentialsWO.IsNull(),
		"is_unknown": data.CredentialsWO.IsUnknown(),
	})

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := data.Path.ValueString()

	// Step 1: Create the mount using the helper
	tflog.Debug(ctx, "Creating GCP KMS mount", map[string]any{"path": mountPath})
	if err := mount.CreateMount(ctx, cli, &data.MountModel, consts.MountTypeGCPKMS, r.Meta()); err != nil {
		resp.Diagnostics.AddError(
			"Error creating GCP KMS mount",
			fmt.Sprintf("Could not create mount at %s: %s", mountPath, err),
		)
		return
	}

	// Step 2: Configure the backend with credentials
	configPath := fmt.Sprintf("%s/config", mountPath)

	// Always include credentials during Create
	configData, diags := buildBackendConfigFromModel(ctx, &data, true)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Configuring GCP KMS backend", map[string]any{"path": configPath})
	if _, err := cli.Logical().WriteWithContext(ctx, configPath, configData); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Step 3: Read back mount information to get computed values
	mountOutput, found, err := mount.ReadMount(ctx, cli, mountPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading GCP KMS mount",
			fmt.Sprintf("Could not read mount at %s: %s", mountPath, err),
		)
		return
	}

	if found {
		data.ApplyMountOutput(mountOutput)
		data.ID = mountOutput.Path
	}

	// Read back the backend config state from Vault to ensure all computed values are set
	// Set the data in state first so Read can use it
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readReq := resource.ReadRequest{State: resp.State}
	readResp := resource.ReadResponse{State: resp.State}
	r.Read(ctx, readReq, &readResp)
	resp.State = readResp.State
	resp.Diagnostics.Append(readResp.Diagnostics...)
}

func (r *GCPKMSSecretBackendResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GCPKMSSecretBackendModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := data.Path.ValueString()

	// Step 1: Read mount information to get accessor and other mount-level attributes
	tflog.Debug(ctx, "Reading GCP KMS mount", map[string]any{"path": mountPath})
	mountOutput, found, err := mount.ReadMount(ctx, cli, mountPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading GCP KMS mount",
			fmt.Sprintf("Could not read mount at %s: %s", mountPath, err),
		)
		return
	}

	if !found {
		tflog.Warn(ctx, "GCP KMS mount not found, removing from state", map[string]any{"path": mountPath})
		resp.State.RemoveResource(ctx)
		return
	}

	// Update mount-level attributes from mount output
	data.ApplyMountOutput(mountOutput)
	data.ID = mountOutput.Path

	// Step 2: Read backend configuration
	configPath := fmt.Sprintf("%s/config", mountPath)
	tflog.Debug(ctx, "Reading GCP KMS backend config", map[string]any{"path": configPath})
	secret, err := cli.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	if secret == nil {
		tflog.Warn(ctx, "GCP KMS backend config not found, removing from state", map[string]any{"path": configPath})
		resp.State.RemoveResource(ctx)
		return
	}

	// Only update scopes if they're in the response
	if scopes, ok := secret.Data[consts.FieldScopes].([]interface{}); ok && len(scopes) > 0 {
		scopeList := make([]string, len(scopes))
		for i, s := range scopes {
			scopeList[i] = s.(string)
		}
		scopeTypes, diags := types.SetValueFrom(ctx, types.StringType, scopeList)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Scopes = scopeTypes
	} else {
		// Set to null if not in response
		data.Scopes = types.SetNull(types.StringType)
	}

	// Note: credentials are write-only and won't be returned by the API
	// We keep the values from state

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GCPKMSSecretBackendResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state GCPKMSSecretBackendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Only include credentials if the version changed
	includeCredentials := !plan.CredentialsWOVersion.Equal(state.CredentialsWOVersion)

	if includeCredentials {
		var configModel GCPKMSSecretBackendModel
		resp.Diagnostics.Append(req.Config.Get(ctx, &configModel)...)
		if resp.Diagnostics.HasError() {
			return
		}
		// Copy the write-only credential value from Config into our plan model
		plan.CredentialsWO = configModel.CredentialsWO

		tflog.Debug(ctx, "Update: credentials version changed, including credentials", map[string]any{
			"old_version": state.CredentialsWOVersion.ValueInt64(),
			"new_version": plan.CredentialsWOVersion.ValueInt64(),
		})
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := plan.Path.ValueString()

	// Step 0: Remount in place if the path changed. The path attribute is not
	// RequiresReplace, so a path change is handled as an in-place move rather
	// than a destroy/recreate (which would lose backend data).
	if !plan.Path.Equal(state.Path) {
		oldPath := state.Path.ValueString()
		tflog.Debug(ctx, "Remounting GCP KMS mount", map[string]any{"from": oldPath, "to": mountPath})
		if err := mount.RemountMount(ctx, cli, oldPath, mountPath); err != nil {
			resp.Diagnostics.AddError(
				"Error remounting GCP KMS mount",
				fmt.Sprintf("Could not remount from %s to %s: %s", oldPath, mountPath, err),
			)
			return
		}
	}

	// Step 1: Update mount settings if any mount-related fields changed
	mountFieldsChanged := plan.HasMountChanges(&state.MountModel)

	if mountFieldsChanged {
		tflog.Debug(ctx, "Updating GCP KMS mount settings", map[string]any{"path": mountPath})
		if err := mount.UpdateMount(ctx, cli, &plan.MountModel, &state.MountModel, r.Meta()); err != nil {
			resp.Diagnostics.AddError(
				"Error updating GCP KMS mount",
				fmt.Sprintf("Could not update mount at %s: %s", mountPath, err),
			)
			return
		}
	}

	// Step 2: Update backend configuration if needed
	configPath := fmt.Sprintf("%s/config", mountPath)

	configData, diags := buildBackendConfigFromModel(ctx, &plan, includeCredentials)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating GCP KMS backend config", map[string]any{
		"path":                 configPath,
		"credentials_included": includeCredentials,
	})
	if _, err := cli.Logical().WriteWithContext(ctx, configPath, configData); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	// Set the current plan in state first so Read can use it
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read back the state from Vault to ensure all computed values are set
	readReq := resource.ReadRequest{State: resp.State}
	readResp := resource.ReadResponse{State: resp.State}
	r.Read(ctx, readReq, &readResp)
	resp.State = readResp.State
	resp.Diagnostics.Append(readResp.Diagnostics...)
}

func (r *GCPKMSSecretBackendResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GCPKMSSecretBackendModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := data.Path.ValueString()

	// Delete the mount (which also deletes the backend configuration)
	tflog.Debug(ctx, "Deleting GCP KMS mount", map[string]any{"path": mountPath})
	if err := mount.DeleteMount(ctx, cli, mountPath); err != nil {
		resp.Diagnostics.AddError(
			"Error deleting GCP KMS mount",
			fmt.Sprintf("Could not delete mount at %s: %s", mountPath, err),
		)
		return
	}
}

func (r *GCPKMSSecretBackendResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID is the mount path, e.g. "gcpkms"
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldPath), req.ID)...)

	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

// buildBackendConfigFromModel extracts the configuration data from the model
// and returns a map suitable for writing to Vault's GCP KMS backend config endpoint.
// This helper reduces code duplication between Create and Update methods.
func buildBackendConfigFromModel(ctx context.Context, data *GCPKMSSecretBackendModel, includeCredentials bool) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	configData := make(map[string]interface{})

	// Only include credentials when explicitly requested
	// Empty string is valid and tells Vault to use Default Application Credentials
	if includeCredentials {
		configData[consts.FieldCredentials] = data.CredentialsWO.ValueString()
	}

	// Add scopes if provided
	if !data.Scopes.IsNull() && !data.Scopes.IsUnknown() {
		var scopes []string
		diags.Append(data.Scopes.ElementsAs(ctx, &scopes, false)...)
		if diags.HasError() {
			return nil, diags
		}
		configData[consts.FieldScopes] = scopes
	}

	return configData, diags
}
