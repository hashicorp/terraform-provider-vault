// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package radius

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/token"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

// defaultMountPath is the default path where RADIUS auth is mounted
const defaultMountPath = "radius"

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &RadiusAuthBackendResource{}

// NewRadiusAuthBackendResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewRadiusAuthBackendResource() resource.Resource {
	return &RadiusAuthBackendResource{}
}

// RadiusAuthBackendResource implements the methods that define this resource
type RadiusAuthBackendResource struct {
	base.ResourceWithConfigure
}

// RadiusAuthBackendModel describes the Terraform resource data model to match the
// resource schema.
type RadiusAuthBackendModel struct {
	token.TokenModel

	Path                     types.String `tfsdk:"path"`
	Host                     types.String `tfsdk:"host"`
	Port                     types.Int64  `tfsdk:"port"`
	SecretWO                 types.String `tfsdk:"secret_wo"`
	UnregisteredUserPolicies types.Set    `tfsdk:"unregistered_user_policies"`
	DialTimeout              types.Int64  `tfsdk:"dial_timeout"`
	ReadTimeout              types.Int64  `tfsdk:"read_timeout"`
	NASPort                  types.Int64  `tfsdk:"nas_port"`
	NASIdentifier            types.String `tfsdk:"nas_identifier"`
}

// RadiusAuthBackendAPIModel describes the Vault API data model.
// Note: Secret is write-only and only used when writing to Vault, not when reading.
// Both json and mapstructure tags are needed:
// - json tags: used by model.ToAPIModel() when reading from Vault
// - mapstructure tags: used by mapstructure.Decode() when writing to Vault
type RadiusAuthBackendAPIModel struct {
	token.TokenAPIModel `mapstructure:",squash"`

	Host                     string   `json:"host,omitempty" mapstructure:"host,omitempty"`
	Port                     int64    `json:"port,omitempty" mapstructure:"port,omitempty"`
	Secret                   string   `json:"secret,omitempty" mapstructure:"secret,omitempty"`
	UnregisteredUserPolicies []string `json:"unregistered_user_policies,omitempty" mapstructure:"unregistered_user_policies,omitempty"`
	DialTimeout              int64    `json:"dial_timeout,omitempty" mapstructure:"dial_timeout,omitempty"`
	ReadTimeout              int64    `json:"read_timeout,omitempty" mapstructure:"read_timeout,omitempty"`
	NASPort                  int64    `json:"nas_port,omitempty" mapstructure:"nas_port,omitempty"`
	NASIdentifier            string   `json:"nas_identifier,omitempty" mapstructure:"nas_identifier,omitempty"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
func (r *RadiusAuthBackendResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_radius_auth_backend"
}

// Schema defines this resource's schema
func (r *RadiusAuthBackendResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				MarkdownDescription: "Path to mount the RADIUS auth backend. Defaults to `radius`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(defaultMountPath),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldHost: schema.StringAttribute{
				MarkdownDescription: "The RADIUS server to connect to. Examples: `radius.myorg.com`, `127.0.0.1`.",
				Required:            true,
			},
			consts.FieldPort: schema.Int64Attribute{
				MarkdownDescription: "The UDP port where the RADIUS server is listening on. Defaults to `1812`.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldRadiusSecretWO: schema.StringAttribute{
				MarkdownDescription: "The RADIUS shared secret. This is a write-only field and will not be read back from Vault.",
				Required:            true,
				WriteOnly:           true,
			},
			consts.FieldRadiusUnregisteredUserPolicies: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "A set of policies to be granted to unregistered users.",
				Optional:            true,
			},
			consts.FieldRadiusDialTimeout: schema.Int64Attribute{
				MarkdownDescription: "Number of seconds to wait for a backend connection before timing out. Defaults to `10`.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldRadiusReadTimeout: schema.Int64Attribute{
				MarkdownDescription: "Number of seconds to wait for a response from the RADIUS server. This is a read-only field returned by Vault.",
				Computed:            true,
			},
			consts.FieldRadiusNASPort: schema.Int64Attribute{
				MarkdownDescription: "The NAS-Port attribute of the RADIUS request. Defaults to `10`.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldRadiusNASIdentifier: schema.StringAttribute{
				MarkdownDescription: "The NAS-Identifier attribute of the RADIUS request. This is a read-only field returned by Vault.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Manages a RADIUS Auth mount in a Vault server.",
	}

	// Add the common token fields and base schema
	token.MustAddBaseAndTokenSchemas(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *RadiusAuthBackendResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RadiusAuthBackendModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read write-only secret from config (write-only fields are not in plan)
	secret, diags := r.readSecretFromConfig(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := strings.Trim(data.Path.ValueString(), "/")

	// Enable the auth backend
	tflog.Debug(ctx, fmt.Sprintf("Enabling RADIUS auth backend at '%s'", mountPath))
	err = vaultClient.Sys().EnableAuthWithOptionsWithContext(ctx, mountPath, &api.EnableAuthOptions{
		Type: consts.MountTypeRadius,
	})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error enabling RADIUS auth backend",
			fmt.Sprintf("Could not enable RADIUS auth backend at '%s': %s", mountPath, err),
		)
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Enabled RADIUS auth backend at '%s'", mountPath))

	// Build the API request
	vaultRequest, apiDiags := r.getApiModel(ctx, &data, secret)
	resp.Diagnostics.Append(apiDiags...)
	if resp.Diagnostics.HasError() {
		// Try to clean up the mount on failure
		_ = vaultClient.Sys().DisableAuthWithContext(ctx, mountPath)
		return
	}

	// Write config to Vault
	configPath := r.configPath(mountPath)
	tflog.Debug(ctx, fmt.Sprintf("Writing RADIUS auth config to '%s'", configPath))
	_, err = vaultClient.Logical().WriteWithContext(ctx, configPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error writing RADIUS auth config",
			fmt.Sprintf("Could not write config to '%s': %s", configPath, err),
		)
		// Try to clean up the mount on failure
		_ = vaultClient.Sys().DisableAuthWithContext(ctx, mountPath)
		return
	}
	tflog.Info(ctx, fmt.Sprintf("RADIUS auth config successfully written to '%s'", configPath))

	// Read back config from Vault to populate computed fields
	configResp, err := vaultClient.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if configResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	// Populate model from API response
	populateDiags := r.populateDataModelFromApi(ctx, &data, configResp)
	resp.Diagnostics.Append(populateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set path (used as resource identifier)
	data.Path = types.StringValue(mountPath)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *RadiusAuthBackendResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RadiusAuthBackendModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := data.Path.ValueString()
	if mountPath == "" {
		mountPath = defaultMountPath
	}
	mountPath = strings.Trim(mountPath, "/")

	// Read config
	configPath := r.configPath(mountPath)
	tflog.Debug(ctx, fmt.Sprintf("Reading RADIUS auth config from '%s'", configPath))
	configResp, err := vaultClient.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if configResp == nil {
		tflog.Warn(ctx, fmt.Sprintf("RADIUS auth config at '%s' not found, removing from state", configPath))
		resp.State.RemoveResource(ctx)
		return
	}

	// Populate model from API response
	populateDiags := r.populateDataModelFromApi(ctx, &data, configResp)
	resp.Diagnostics.Append(populateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update state
	data.Path = types.StringValue(mountPath)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command.
func (r *RadiusAuthBackendResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data RadiusAuthBackendModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read write-only secret from config (write-only fields are not in plan)
	secret, diags := r.readSecretFromConfig(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := strings.Trim(data.Path.ValueString(), "/")

	// Build the API request
	vaultRequest, apiDiags := r.getApiModel(ctx, &data, secret)
	resp.Diagnostics.Append(apiDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write config to Vault
	configPath := r.configPath(mountPath)
	tflog.Debug(ctx, fmt.Sprintf("Writing RADIUS auth config to '%s'", configPath))
	_, err = vaultClient.Logical().WriteWithContext(ctx, configPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error writing RADIUS auth config",
			fmt.Sprintf("Could not write config to '%s': %s", configPath, err),
		)
		return
	}
	tflog.Info(ctx, fmt.Sprintf("RADIUS auth config successfully written to '%s'", configPath))

	// Read back config from Vault to populate computed fields
	configResp, err := vaultClient.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if configResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	// Populate model from API response
	populateDiags := r.populateDataModelFromApi(ctx, &data, configResp)
	resp.Diagnostics.Append(populateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Path = types.StringValue(mountPath)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform destroy command.
func (r *RadiusAuthBackendResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RadiusAuthBackendModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := strings.Trim(data.Path.ValueString(), "/")

	tflog.Debug(ctx, fmt.Sprintf("Disabling RADIUS auth backend at '%s'", mountPath))
	if err := vaultClient.Sys().DisableAuthWithContext(ctx, mountPath); err != nil {
		resp.Diagnostics.AddError(
			"Error disabling RADIUS auth backend",
			fmt.Sprintf("Could not disable RADIUS auth backend at '%s': %s", mountPath, err),
		)
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Disabled RADIUS auth backend at '%s'", mountPath))
}

// ImportState handles resource import
func (r *RadiusAuthBackendResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mountPath := strings.Trim(req.ID, "/")
	if mountPath == "" {
		mountPath = defaultMountPath
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldPath), mountPath)...)

	// Handle namespace import via environment variable
	// See: https://registry.terraform.io/providers/hashicorp/vault/latest/docs#namespace-support
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

// configPath returns the Vault API path for RADIUS config
func (r *RadiusAuthBackendResource) configPath(mountPath string) string {
	return fmt.Sprintf("auth/%s/config", mountPath)
}

// readSecretFromConfig reads the write-only secret from the Terraform config.
// Write-only fields are not included in the plan, so they must be read from config directly.
func (r *RadiusAuthBackendResource) readSecretFromConfig(ctx context.Context, config tfsdk.Config) (string, diag.Diagnostics) {
	var secret *string
	diags := config.GetAttribute(ctx, path.Root(consts.FieldRadiusSecretWO), &secret)
	if diags.HasError() {
		return "", diags
	}
	if secret == nil {
		return "", diags
	}
	return *secret, diags
}

// getApiModel builds the Vault API request map from the Terraform data model.
// Note: secret is write-only so it is never part of the plan and must be passed separately.
func (r *RadiusAuthBackendResource) getApiModel(ctx context.Context, data *RadiusAuthBackendModel, secret string) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Build token API model
	var tokenAPI token.TokenAPIModel
	tokenDiags := token.PopulateTokenAPIFromModel(ctx, &data.TokenModel, &tokenAPI)
	diags.Append(tokenDiags...)
	if diags.HasError() {
		return nil, diags
	}

	// Convert Set to comma-separated string for Vault API
	// Note: Vault RADIUS API accepts comma-separated string but returns array
	policiesStr, policyDiags := util.SetToCommaSeparatedString(ctx, data.UnregisteredUserPolicies)
	diags.Append(policyDiags...)
	if diags.HasError() {
		return nil, diags
	}

	// Build API model without UnregisteredUserPolicies (we'll add it manually as string)
	// Note: DialTimeout and NASPort are set to 0 here; we'll add non-zero values manually
	// to avoid sending 0 which Vault interprets as "use default"
	apiModel := RadiusAuthBackendAPIModel{
		TokenAPIModel: tokenAPI,
		Host:          data.Host.ValueString(),
		Port:          data.Port.ValueInt64(),
		Secret:        secret,
	}

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		diags.AddError("Failed to decode RADIUS config API model to map", err.Error())
		return nil, diags
	}

	// Only include integer fields if they have non-zero values
	// Vault treats 0 as "use default" and returns the default value, causing state inconsistency
	if !data.DialTimeout.IsNull() && !data.DialTimeout.IsUnknown() && data.DialTimeout.ValueInt64() != 0 {
		vaultRequest[consts.FieldRadiusDialTimeout] = data.DialTimeout.ValueInt64()
	}
	if !data.NASPort.IsNull() && !data.NASPort.IsUnknown() && data.NASPort.ValueInt64() != 0 {
		vaultRequest[consts.FieldRadiusNASPort] = data.NASPort.ValueInt64()
	}

	// Always send unregistered_user_policies as comma-separated string (Vault API requirement)
	// Empty string clears policies, non-empty string sets them
	vaultRequest[consts.FieldRadiusUnregisteredUserPolicies] = policiesStr

	return vaultRequest, diags
}

// populateDataModelFromApi maps the Vault API response to the Terraform data model.
func (r *RadiusAuthBackendResource) populateDataModelFromApi(ctx context.Context, data *RadiusAuthBackendModel, resp *api.Secret) diag.Diagnostics {
	var diags diag.Diagnostics

	if resp == nil || resp.Data == nil {
		diags.AddError("Missing data in API response", "The API response or response data was nil.")
		return diags
	}

	var apiModel RadiusAuthBackendAPIModel
	if err := model.ToAPIModel(resp.Data, &apiModel); err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return diags
	}

	// Map API response to model
	data.Host = types.StringValue(apiModel.Host)
	data.Port = types.Int64Value(apiModel.Port)
	// Convert []string from API to Set for Terraform
	policies, policyDiags := util.StringSliceToSet(ctx, apiModel.UnregisteredUserPolicies)
	diags.Append(policyDiags...)
	if diags.HasError() {
		return diags
	}
	data.UnregisteredUserPolicies = policies
	data.DialTimeout = types.Int64Value(apiModel.DialTimeout)
	data.ReadTimeout = types.Int64Value(apiModel.ReadTimeout)
	data.NASPort = types.Int64Value(apiModel.NASPort)
	data.NASIdentifier = types.StringValue(apiModel.NASIdentifier)

	// Populate token fields
	tokenDiags := token.PopulateTokenModelFromAPI(ctx, &data.TokenModel, &apiModel.TokenAPIModel)
	diags.Append(tokenDiags...)

	return diags
}
