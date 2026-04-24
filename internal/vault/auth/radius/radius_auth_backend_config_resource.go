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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/api"
)

// defaultMountPath is the default path where RADIUS auth is mounted
const defaultMountPath = "radius"

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &RadiusAuthBackendConfigResource{}
var _ resource.ResourceWithImportState = &RadiusAuthBackendConfigResource{}

// NewRadiusAuthBackendConfigResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewRadiusAuthBackendConfigResource() resource.Resource {
	return &RadiusAuthBackendConfigResource{}
}

// RadiusAuthBackendConfigResource implements the methods that define this resource
type RadiusAuthBackendConfigResource struct {
	base.ResourceWithConfigure
}

// RadiusAuthBackendModel describes the Terraform resource data model to match the
// resource schema.
type RadiusAuthBackendModel struct {
	token.TokenModel

	Mount                    types.String `tfsdk:"mount"`
	Host                     types.String `tfsdk:"host"`
	Port                     types.Int64  `tfsdk:"port"`
	SecretWO                 types.String `tfsdk:"secret_wo"`
	SecretWOVersion          types.Int64  `tfsdk:"secret_wo_version"`
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

	Host                     string   `json:"host" mapstructure:"host"`
	Port                     int64    `json:"port,omitempty" mapstructure:"port,omitempty"`
	Secret                   string   `json:"secret" mapstructure:"secret"`
	UnregisteredUserPolicies []string `json:"unregistered_user_policies" mapstructure:"unregistered_user_policies"`
	DialTimeout              int64    `json:"dial_timeout,omitempty" mapstructure:"dial_timeout,omitempty"`
	ReadTimeout              int64    `json:"read_timeout,omitempty" mapstructure:"read_timeout,omitempty"`
	NASPort                  int64    `json:"nas_port,omitempty" mapstructure:"nas_port,omitempty"`
	NASIdentifier            string   `json:"nas_identifier" mapstructure:"nas_identifier"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
func (r *RadiusAuthBackendConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_radius_auth_backend"
}

// Schema defines this resource's schema
func (r *RadiusAuthBackendConfigResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path of the enabled RADIUS auth backend mount to configure.",
				Required:            true,
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
			consts.FieldSecretWO: schema.StringAttribute{
				MarkdownDescription: "The RADIUS shared secret. This is a write-only field and will not be read back from Vault.",
				Required:            true,
				WriteOnly:           true,
				Sensitive:           true,
			},
			consts.FieldSecretWOVersion: schema.Int64Attribute{
				Required: true,
				MarkdownDescription: "Version counter for the write-only `secret_wo` field. " +
					"Since write-only values are not stored in state, Terraform cannot detect when the secret changes. " +
					"Increment this value whenever you update `secret_wo` so Terraform detects the change and applies an update.",
			},
			consts.FieldUnregisteredUserPolicies: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "A set of policies to be granted to unregistered users.",
				Optional:            true,
			},
			consts.FieldDialTimeout: schema.Int64Attribute{
				MarkdownDescription: "Number of seconds to wait for a backend connection before timing out. Defaults to `10`. If removed from configuration after being set, Vault retains the previously stored value.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldReadTimeout: schema.Int64Attribute{
				MarkdownDescription: "Number of seconds to wait for a response from the RADIUS server. Defaults to `10`. If removed from configuration after being set, Vault retains the previously stored value.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldNASPort: schema.Int64Attribute{
				MarkdownDescription: "The NAS-Port attribute of the RADIUS request. Defaults to `10`. If removed from configuration after being set, Vault retains the previously stored value.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldNASIdentifier: schema.StringAttribute{
				MarkdownDescription: "The NAS-Identifier attribute of the RADIUS request. This is a read-only field returned by Vault.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Manages RADIUS auth backend configuration for an existing auth mount in Vault.",
	}

	// Add the common token fields and base schema
	token.MustAddBaseAndTokenSchemas(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *RadiusAuthBackendConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RadiusAuthBackendModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.upsertConfig(ctx, &data, req.Config, errutil.VaultCreateErr)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *RadiusAuthBackendConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

	mountPath := r.mountPath(data.Mount)

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
	data.Mount = types.StringValue(mountPath)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command.
func (r *RadiusAuthBackendConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan RadiusAuthBackendModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.upsertConfig(ctx, &plan, req.Config, errutil.VaultUpdateErr)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// upsertConfig reads the write-only secret from Terraform config, writes the
// RADIUS backend configuration, and refreshes the model from Vault's
// read-after-write response.
func (r *RadiusAuthBackendConfigResource) upsertConfig(ctx context.Context, data *RadiusAuthBackendModel, config tfsdk.Config, writeErr func(error) (string, string)) diag.Diagnostics {
	var diags diag.Diagnostics

	secret, secretDiags := r.readSecretForWriteFromConfig(ctx, config)
	diags.Append(secretDiags...)
	if diags.HasError() {
		return diags
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return diags
	}

	mountPath := r.mountPath(data.Mount)

	vaultRequest, apiDiags := r.getApiModel(ctx, data, secret)
	diags.Append(apiDiags...)
	if diags.HasError() {
		return diags
	}

	configResp, writeDiags := r.writeConfig(ctx, vaultClient, mountPath, vaultRequest, writeErr)
	diags.Append(writeDiags...)
	if diags.HasError() {
		return diags
	}

	diags.Append(r.populateDataModelFromApi(ctx, data, configResp)...)
	if diags.HasError() {
		return diags
	}

	data.Mount = types.StringValue(mountPath)

	return diags
}

// Delete is called during the terraform destroy command.
func (r *RadiusAuthBackendConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RadiusAuthBackendModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mountPath := r.mountPath(data.Mount)

	resp.Diagnostics.AddWarning(
		"RADIUS auth backend configuration remains in Vault",
		fmt.Sprintf("Removing this resource from Terraform state does not disable the RADIUS auth mount or clear the config at '%s'. Manage the mount lifecycle separately with vault_auth_backend if needed.", r.configPath(mountPath)),
	)
}

// ImportState handles resource import
func (r *RadiusAuthBackendConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mountPath, err := extractRadiusConfigMountFromID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s", req.ID, err.Error()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mountPath)...)

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

// extractRadiusConfigMountFromID parses an import identifier in the form
// auth/<mount>/config and returns the normalized mount path.
func extractRadiusConfigMountFromID(id string) (string, error) {
	id = strings.Trim(id, "/")
	if !strings.HasPrefix(id, "auth/") || !strings.HasSuffix(id, "/config") {
		return "", fmt.Errorf("expected import ID in the format auth/<mount>/config")
	}

	mountPath := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(id, "auth/"), "/config"), "/")
	if mountPath == "" || strings.Contains(mountPath, "//") {
		return "", fmt.Errorf("expected import ID in the format auth/<mount>/config")
	}

	return mountPath, nil
}

// configPath returns the Vault API path for RADIUS config
func (r *RadiusAuthBackendConfigResource) configPath(mountPath string) string {
	return fmt.Sprintf("auth/%s/config", mountPath)
}

// mountPath normalizes the configured mount name before it is used in Vault
// API paths.
func (r *RadiusAuthBackendConfigResource) mountPath(mount types.String) string {
	return strings.Trim(mount.ValueString(), "/")
}

// writeConfig writes the RADIUS backend configuration and re-reads it so state
// reflects the values returned by Vault.
func (r *RadiusAuthBackendConfigResource) writeConfig(ctx context.Context, vaultClient *api.Client, mountPath string, vaultRequest map[string]any, writeErr func(error) (string, string)) (*api.Secret, diag.Diagnostics) {
	var diags diag.Diagnostics

	configPath := r.configPath(mountPath)
	tflog.Debug(ctx, fmt.Sprintf("Writing RADIUS auth config to '%s'", configPath))
	_, err := vaultClient.Logical().WriteWithContext(ctx, configPath, vaultRequest)
	if err != nil {
		diags.AddError(writeErr(err))
		return nil, diags
	}
	tflog.Info(ctx, fmt.Sprintf("RADIUS auth config successfully written to '%s'", configPath))

	configResp, err := vaultClient.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return nil, diags
	}
	if configResp == nil {
		diags.AddError(errutil.VaultReadResponseNil())
		return nil, diags
	}

	return configResp, diags
}

// readSecretForWriteFromConfig reads the write-only secret from Terraform
// config for create/update requests. Vault does not reliably return this field
// on read, and write-only attributes are not stored in plan or state.
func (r *RadiusAuthBackendConfigResource) readSecretForWriteFromConfig(ctx context.Context, config tfsdk.Config) (string, diag.Diagnostics) {
	var secret *string
	diags := config.GetAttribute(ctx, path.Root(consts.FieldSecretWO), &secret)
	if diags.HasError() || secret == nil {
		return "", diags
	}
	return *secret, diags
}

// getApiModel builds the Vault API request map from the Terraform data model.
// Note: secret is write-only so it is never part of the plan and must be passed from config for each write.
func (r *RadiusAuthBackendConfigResource) getApiModel(ctx context.Context, data *RadiusAuthBackendModel, secret string) (map[string]any, diag.Diagnostics) {
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
	var elements []string
	policiesDiags := data.UnregisteredUserPolicies.ElementsAs(ctx, &elements, false)
	diags.Append(policiesDiags...)
	if diags.HasError() {
		return nil, diags
	}
	policiesStr := strings.Join(elements, ",")

	// Build API model without UnregisteredUserPolicies (we'll add it manually as string).
	// The timeout/NAS fields use omitempty so removing them from configuration omits
	// them from the request, matching Vault's retain-on-update behavior.
	apiModel := RadiusAuthBackendAPIModel{
		TokenAPIModel: tokenAPI,
		Host:          data.Host.ValueString(),
		Port:          data.Port.ValueInt64(),
		Secret:        secret,
		DialTimeout:   data.DialTimeout.ValueInt64(),
		ReadTimeout:   data.ReadTimeout.ValueInt64(),
		NASPort:       data.NASPort.ValueInt64(),
	}

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		diags.AddError("Failed to decode RADIUS config API model to map", err.Error())
		return nil, diags
	}

	// Always send unregistered_user_policies as comma-separated string (Vault API requirement)
	// Empty string clears policies, non-empty string sets them
	vaultRequest[consts.FieldUnregisteredUserPolicies] = policiesStr

	// alias_metadata requires Vault Enterprise 1.21+
	if meta := r.Meta(); meta == nil || !meta.IsAPISupported(provider.VaultVersion121) || !meta.IsEnterpriseSupported() {
		delete(vaultRequest, consts.FieldAliasMetadata)
	}

	return vaultRequest, diags
}

// populateDataModelFromApi maps the Vault API response to the Terraform data model.
func (r *RadiusAuthBackendConfigResource) populateDataModelFromApi(ctx context.Context, data *RadiusAuthBackendModel, resp *api.Secret) diag.Diagnostics {
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
	if len(apiModel.UnregisteredUserPolicies) == 0 {
		if data.UnregisteredUserPolicies.IsNull() || data.UnregisteredUserPolicies.IsUnknown() {
			data.UnregisteredUserPolicies = types.SetNull(types.StringType)
		} else {
			policies, setDiags := types.SetValueFrom(ctx, types.StringType, []string{})
			if setDiags.HasError() {
				return setDiags
			}
			data.UnregisteredUserPolicies = policies
		}
	} else {
		policies, setDiags := types.SetValueFrom(ctx, types.StringType, apiModel.UnregisteredUserPolicies)
		if setDiags.HasError() {
			return setDiags
		}
		data.UnregisteredUserPolicies = policies
	}
	data.DialTimeout = types.Int64Value(apiModel.DialTimeout)
	data.ReadTimeout = types.Int64Value(apiModel.ReadTimeout)
	data.NASPort = types.Int64Value(apiModel.NASPort)
	data.NASIdentifier = types.StringValue(apiModel.NASIdentifier)

	// Save alias_metadata before populating token fields, as Vault CE doesn't return it
	savedAliasMetadata := data.TokenModel.AliasMetadata

	// Populate token fields
	tokenDiags := token.PopulateTokenModelFromAPI(ctx, &data.TokenModel, &apiModel.TokenAPIModel)
	diags.Append(tokenDiags...)

	// Restore alias_metadata if Vault doesn't support it (CE or < 1.21)
	// This prevents state inconsistency when user configures alias_metadata on unsupported Vault
	if meta := r.Meta(); meta == nil || !meta.IsAPISupported(provider.VaultVersion121) || !meta.IsEnterpriseSupported() {
		data.TokenModel.AliasMetadata = savedAliasMetadata
	}

	return diags
}
