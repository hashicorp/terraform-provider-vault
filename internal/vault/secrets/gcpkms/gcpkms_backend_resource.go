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
	Credentials          types.String `tfsdk:"credentials"`
	CredentialsWO        types.String `tfsdk:"credentials_wo"`
	CredentialsWOVersion types.Int64  `tfsdk:"credentials_wo_version"`
	Scopes               types.List   `tfsdk:"scopes"`
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
			consts.FieldCredentials: schema.StringAttribute{
				MarkdownDescription: "JSON-encoded GCP service account credentials. Cannot be used with `credentials_wo`.",
				Optional:            true,
				Sensitive:           true,
			},
			consts.FieldCredentialsWO: schema.StringAttribute{
				MarkdownDescription: "Write-only JSON-encoded GCP service account credentials. Cannot be used with `credentials`.",
				Optional:            true,
				Sensitive:           true,
			},
			consts.FieldCredentialsWOVersion: schema.Int64Attribute{
				MarkdownDescription: "Version number for the write-only credentials. Increment this to force credential rotation.",
				Optional:            true,
			},
			consts.FieldScopes: schema.ListAttribute{
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

	// Validate that exactly one of credentials or credentials_wo is provided
	hasCredentials := !data.Credentials.IsNull() && data.Credentials.ValueString() != ""
	hasCredentialsWO := !data.CredentialsWO.IsNull() && data.CredentialsWO.ValueString() != ""

	if !hasCredentials && !hasCredentialsWO {
		resp.Diagnostics.AddError(
			"Missing required field",
			"Either 'credentials' or 'credentials_wo' must be provided",
		)
		return
	}

	if hasCredentials && hasCredentialsWO {
		resp.Diagnostics.AddError(
			"Conflicting fields",
			"Only one of 'credentials' or 'credentials_wo' can be provided, not both",
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

	// Configure the backend
	configPath := fmt.Sprintf("%s/config", mountPath)

	configData, diags := buildBackendConfigFromModel(ctx, &data, hasCredentials)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("[DEBUG] Configuring GCP KMS backend at %q", configPath)
	if _, err := cli.Logical().WriteWithContext(ctx, configPath, configData); err != nil {
		resp.Diagnostics.AddError(
			"Error configuring GCP KMS backend",
			fmt.Sprintf("Error configuring GCP KMS backend at path %q: %s", configPath, err),
		)
		return
	}

	// Set ID
	data.ID = types.StringValue(mountPath)

	// Read back the state from Vault to ensure all computed values are set
	readReq := resource.ReadRequest{State: resp.State}
	readResp := resource.ReadResponse{State: resp.State}

	// Set the ID in state first so Read can use it
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readReq.State = resp.State
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
		scopeTypes, diags := types.ListValueFrom(ctx, types.StringType, scopeList)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Scopes = scopeTypes
	} else {
		// Set to null if not in response
		data.Scopes = types.ListNull(types.StringType)
	}

	// Set ID to the mount path
	data.ID = types.StringValue(mountPath)

	// Note: credentials are write-only and won't be returned by the API
	// We keep the values from state

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GCPKMSSecretBackendResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data GCPKMSSecretBackendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate that exactly one of credentials or credentials_wo is provided
	hasCredentials := !data.Credentials.IsNull() && data.Credentials.ValueString() != ""
	hasCredentialsWO := !data.CredentialsWO.IsNull() && data.CredentialsWO.ValueString() != ""

	if !hasCredentials && !hasCredentialsWO {
		resp.Diagnostics.AddError(
			"Missing required field",
			"Either 'credentials' or 'credentials_wo' must be provided",
		)
		return
	}

	if hasCredentials && hasCredentialsWO {
		resp.Diagnostics.AddError(
			"Conflicting fields",
			"Only one of 'credentials' or 'credentials_wo' can be provided, not both",
		)
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := data.Path.ValueString()
	configPath := fmt.Sprintf("%s/config", mountPath)

	configData, diags := buildBackendConfigFromModel(ctx, &data, hasCredentials)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("[DEBUG] Updating GCP KMS backend config at %q", configPath)
	if _, err := cli.Logical().WriteWithContext(ctx, configPath, configData); err != nil {
		resp.Diagnostics.AddError(
			"Error updating GCP KMS backend config",
			fmt.Sprintf("Error updating GCP KMS backend config at path %q: %s", configPath, err),
		)
		return
	}

	// Read back the state from Vault to ensure all computed values are set
	readReq := resource.ReadRequest{State: resp.State}
	readResp := resource.ReadResponse{State: resp.State}

	// Set the current state first so Read can use it
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readReq.State = resp.State
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
func buildBackendConfigFromModel(ctx context.Context, data *GCPKMSSecretBackendModel, hasCredentials bool) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	configData := make(map[string]interface{})

	// Add credentials (either read-write or write-only)
	if hasCredentials {
		configData["credentials"] = data.Credentials.ValueString()
	} else {
		configData["credentials"] = data.CredentialsWO.ValueString()
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
