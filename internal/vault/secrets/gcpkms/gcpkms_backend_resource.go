// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
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
	base.WithImportByID
}

// GCPKMSSecretBackendModel describes the Terraform resource data model
type GCPKMSSecretBackendModel struct {
	base.BaseModelLegacy

	Path                 types.String `tfsdk:"path"`
	CredentialsWO        types.String `tfsdk:"credentials_wo"`
	CredentialsWOVersion types.Int64  `tfsdk:"credentials_wo_version"`
	Scopes               types.Set    `tfsdk:"scopes"`
}

func (r *GCPKMSSecretBackendResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcpkms_secret_backend"
}

func (r *GCPKMSSecretBackendResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				MarkdownDescription: "Path where the GCP KMS secrets engine will be mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldCredentialsWO: schema.StringAttribute{
				MarkdownDescription: "JSON-encoded GCP service account credentials. This value is write-only and will not be stored in Terraform state. Requires Terraform 1.11+.",
				Required:            true,
				Sensitive:           true,
				WriteOnly:           true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldCredentialsWOVersion: schema.Int64Attribute{
				MarkdownDescription: "Version number for the write-only credentials. Increment this value to trigger a credential rotation. Changing this value will cause the credentials to be re-sent to Vault during the next apply.",
				Required:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldScopes: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "OAuth scopes to use for GCP API requests. Defaults to ['https://www.googleapis.com/auth/cloudkms'].",
				Optional:            true,
				Computed:            true,
			},
		},
		MarkdownDescription: "Manages a GCP KMS secrets engine backend in Vault.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
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

	log.Printf("[DEBUG] Create: credentials_wo from Config - is_null: %v, is_unknown: %v, length: %d",
		data.CredentialsWO.IsNull(), data.CredentialsWO.IsUnknown(), len(data.CredentialsWO.ValueString()))

	// Validate that credentials are actually present
	if data.CredentialsWO.IsNull() || data.CredentialsWO.IsUnknown() || data.CredentialsWO.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing credentials",
			"The credentials_wo field is required but was empty or null. "+
				"Ensure you are providing valid GCP service account credentials.",
		)
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Mount the backend
	mountPath := data.Path.ValueString()
	log.Printf("[DEBUG] Mounting GCP KMS secrets engine at %q", mountPath)

	mountConfig := &api.MountInput{
		Type: consts.MountTypeGCPKMS,
	}

	if err := cli.Sys().MountWithContext(ctx, mountPath, mountConfig); err != nil {
		resp.Diagnostics.AddError(
			"Error mounting GCP KMS backend",
			fmt.Sprintf("Error mounting GCP KMS backend at path %q: %s", mountPath, err),
		)
		return
	}

	// Configure the backend with credentials
	configPath := fmt.Sprintf("%s/config", mountPath)

	// Always include credentials during Create
	configData, diags := buildBackendConfigFromModel(ctx, &data, true)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("[DEBUG] Configuring GCP KMS backend at %q (credentials included: true, credentials length: %d)",
		configPath, len(data.CredentialsWO.ValueString()))
	if _, err := cli.Logical().WriteWithContext(ctx, configPath, configData); err != nil {
		resp.Diagnostics.AddError(
			"Error configuring GCP KMS backend",
			fmt.Sprintf("Error configuring GCP KMS backend at path %q: %s", configPath, err),
		)
		return
	}

	// Read back the state from Vault to ensure all computed values are set
	// Set the data in state first so Read can use it
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readReq := resource.ReadRequest{State: resp.State}
	readResp := resource.ReadResponse{State: resp.State}
	r.Read(ctx, readReq, &readResp)
	resp.Diagnostics.Append(readResp.Diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.State = readResp.State
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
	configPath := fmt.Sprintf("%s/config", mountPath)

	log.Printf("[DEBUG] Reading GCP KMS backend config from %q", configPath)
	secret, err := cli.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading GCP KMS backend config",
			fmt.Sprintf("Error reading GCP KMS backend config from path %q: %s", configPath, err),
		)
		return
	}

	if secret == nil {
		log.Printf("[WARN] GCP KMS backend config not found at %q, removing from state", configPath)
		resp.State.RemoveResource(ctx)
		return
	}

	// Only update scopes if they're in the response
	if scopes, ok := secret.Data["scopes"].([]interface{}); ok && len(scopes) > 0 {
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

	// Set ID to the mount path
	data.ID = types.StringValue(mountPath)

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

		log.Printf("[DEBUG] Update: credentials version changed (%v -> %v), including credentials (length: %d)",
			state.CredentialsWOVersion.ValueInt64(), plan.CredentialsWOVersion.ValueInt64(),
			len(plan.CredentialsWO.ValueString()))

		// Validate that credentials are actually present
		if plan.CredentialsWO.IsNull() || plan.CredentialsWO.IsUnknown() || plan.CredentialsWO.ValueString() == "" {
			resp.Diagnostics.AddError(
				"Missing credentials",
				"The credentials_wo field is required when credentials_wo_version changes, "+
					"but was empty or null. Ensure you are providing valid GCP service account credentials.",
			)
			return
		}
	} else {
		log.Printf("[DEBUG] Update: credentials version unchanged (%v), not sending credentials to Vault",
			state.CredentialsWOVersion.ValueInt64())
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := plan.Path.ValueString()
	configPath := fmt.Sprintf("%s/config", mountPath)

	configData, diags := buildBackendConfigFromModel(ctx, &plan, includeCredentials)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("[DEBUG] Updating GCP KMS backend config at %q (credentials included: %v)",
		configPath, includeCredentials)
	if _, err := cli.Logical().WriteWithContext(ctx, configPath, configData); err != nil {
		resp.Diagnostics.AddError(
			"Error updating GCP KMS backend config",
			fmt.Sprintf("Error updating GCP KMS backend config at path %q: %s", configPath, err),
		)
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
	resp.Diagnostics.Append(readResp.Diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.State = readResp.State
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
	log.Printf("[DEBUG] Unmounting GCP KMS backend at %q", mountPath)

	if err := cli.Sys().UnmountWithContext(ctx, mountPath); err != nil {
		resp.Diagnostics.AddError(
			"Error unmounting GCP KMS backend",
			fmt.Sprintf("Error unmounting GCP KMS backend at path %q: %s", mountPath, err),
		)
		return
	}
}

func (r *GCPKMSSecretBackendResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldPath), req, resp)
}

// buildBackendConfigFromModel extracts the configuration data from the model
// and returns a map suitable for writing to Vault's GCP KMS backend config endpoint.
// This helper reduces code duplication between Create and Update methods.
func buildBackendConfigFromModel(ctx context.Context, data *GCPKMSSecretBackendModel, includeCredentials bool) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	configData := make(map[string]interface{})

	// Only include credentials when explicitly requested
	if includeCredentials {
		creds := data.CredentialsWO.ValueString()
		if creds == "" {
			diags.AddError(
				"Missing credentials",
				"Credentials are required but the value was empty. "+
					"This may indicate that the write-only field was not properly read from the configuration. "+
					"Ensure you are providing valid GCP service account credentials via the credentials_wo field.",
			)
			return nil, diags
		}
		configData["credentials"] = creds
		log.Printf("[DEBUG] buildBackendConfigFromModel: credentials included (length: %d)", len(creds))
	} else {
		log.Printf("[DEBUG] buildBackendConfigFromModel: credentials NOT included (version unchanged)")
	}

	// Add scopes if provided
	if !data.Scopes.IsNull() && !data.Scopes.IsUnknown() {
		var scopes []string
		diags.Append(data.Scopes.ElementsAs(ctx, &scopes, false)...)
		if diags.HasError() {
			return nil, diags
		}
		configData["scopes"] = scopes
	}

	return configData, diags
}
