// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

var kerberosConfigPathRegexp = regexp.MustCompile("^auth/(.+)/config$")

var (
	_ resource.Resource                = (*kerberosAuthBackendConfigResource)(nil)
	_ resource.ResourceWithConfigure   = (*kerberosAuthBackendConfigResource)(nil)
	_ resource.ResourceWithImportState = (*kerberosAuthBackendConfigResource)(nil)
)

// NewKerberosAuthBackendConfigResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewKerberosAuthBackendConfigResource() resource.Resource {
	return &kerberosAuthBackendConfigResource{}
}

// kerberosAuthBackendConfigResource implements the methods that define this resource
type kerberosAuthBackendConfigResource struct {
	base.ResourceWithConfigure
}

// kerberosAuthBackendConfigModel describes the Terraform resource data model to match the
// resource schema.
type kerberosAuthBackendConfigModel struct {
	base.BaseModel
	Mount              types.String `tfsdk:"mount"`
	KeytabWO           types.String `tfsdk:"keytab_wo"`
	ServiceAccount     types.String `tfsdk:"service_account"`
	RemoveInstanceName types.Bool   `tfsdk:"remove_instance_name"`
	AddGroupAliases    types.Bool   `tfsdk:"add_group_aliases"`
}

// kerberosAuthBackendConfigAPIModel describes the Vault API response structure.
type kerberosAuthBackendConfigAPIModel struct {
	ServiceAccount     string `json:"service_account" mapstructure:"service_account"`
	RemoveInstanceName bool   `json:"remove_instance_name" mapstructure:"remove_instance_name"`
	AddGroupAliases    bool   `json:"add_group_aliases" mapstructure:"add_group_aliases"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
func (r *kerberosAuthBackendConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kerberos_auth_backend_config"
}

func (r *kerberosAuthBackendConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the Kerberos authentication method configuration in Vault.\n\n" +
			"**Note:** Vault does not support deleting auth backend configurations via the API. " +
			"When this resource is destroyed or replaced (e.g., when changing the `mount`), " +
			"it is only removed from Terraform state. The configuration remains in Vault until " +
			"the auth mount itself is deleted.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Required:    true,
				Description: "Path where the Kerberos auth method is mounted.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeytabWO: schema.StringAttribute{
				Required:    true,
				WriteOnly:   true,
				Sensitive:   true,
				Description: "Base64-encoded keytab file content (write-only). Must contain an entry matching service_account.",
			},
			consts.FieldServiceAccount: schema.StringAttribute{
				Required:    true,
				Description: "The Kerberos service account associated with the keytab entry (e.g., 'vault_svc').",
			},
			consts.FieldRemoveInstanceName: schema.BoolAttribute{
				Optional:    true,
				Description: "Removes instance names from Kerberos service principal names. Default: false.",
			},
			consts.FieldAddGroupAliases: schema.BoolAttribute{
				Optional:    true,
				Description: "Adds group aliases during authentication. Default: false.",
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *kerberosAuthBackendConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config kerberosAuthBackendConfigModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeConfig(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

func (r *kerberosAuthBackendConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var config kerberosAuthBackendConfigModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeConfig(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// writeConfig is a reusable helper that writes configuration to Vault and reads it back.
// Used by both Create and Update operations.
func (r *kerberosAuthBackendConfigResource) writeConfig(ctx context.Context, config *kerberosAuthBackendConfigModel) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), config.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return diags
	}

	mount := strings.Trim(config.Mount.ValueString(), "/")
	configPath := r.configPath(mount)

	// Build the API request
	vaultRequest, apiDiags := r.getApiModel(config)
	diags.Append(apiDiags...)
	if diags.HasError() {
		return diags
	}

	// Write config to Vault
	tflog.Debug(ctx, fmt.Sprintf("Writing Kerberos auth backend config to '%s'", configPath))
	_, err = vaultClient.Logical().WriteWithContext(ctx, configPath, vaultRequest)
	if err != nil {
		diags.AddError(
			"Error writing Kerberos auth backend config",
			fmt.Sprintf("Could not write Kerberos auth backend config to '%s': %s", configPath, err),
		)
		return diags
	}
	tflog.Info(ctx, fmt.Sprintf("Kerberos auth backend config successfully written to '%s'", configPath))

	// Read back the configuration
	found, readDiags := r.read(ctx, config)
	diags.Append(readDiags...)
	if diags.HasError() {
		return diags
	}
	if !found {
		diags.AddError(
			"Error reading back Kerberos auth backend config after write",
			fmt.Sprintf("Config at '%s' was not found after successful write", r.configPath(strings.Trim(config.Mount.ValueString(), "/"))),
		)
		return diags
	}

	return diags
}

func (r *kerberosAuthBackendConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state kerberosAuthBackendConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read config from Vault
	found, readDiags := r.read(ctx, &state)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If not found, remove from state
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// read is a reusable helper that reads configuration from Vault.
// Returns true if the config was found, false if not found.
func (r *kerberosAuthBackendConfigResource) read(ctx context.Context, config *kerberosAuthBackendConfigModel) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), config.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return false, diags
	}

	mount := strings.Trim(config.Mount.ValueString(), "/")
	configPath := r.configPath(mount)

	tflog.Debug(ctx, fmt.Sprintf("Reading Kerberos auth backend config from '%s'", configPath))
	resp, err := vaultClient.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return false, diags
	}

	if resp == nil {
		tflog.Warn(ctx, fmt.Sprintf("Kerberos auth backend config at '%s' not found, removing from state", configPath))
		return false, diags
	}

	// Populate model from API response
	populateDiags := r.populateDataModelFromApi(config, resp.Data)
	diags.Append(populateDiags...)
	return true, diags
}

// Delete is called during the terraform destroy command.
func (r *kerberosAuthBackendConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state kerberosAuthBackendConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mount := strings.Trim(state.Mount.ValueString(), "/")
	configPath := fmt.Sprintf("auth/%s/config", mount)

	// Configuration endpoints cannot be deleted from Vault, only the auth mount itself can be deleted.
	// This function only removes the resource from Terraform state.
	tflog.Debug(ctx, "Removing Kerberos auth backend config from Terraform state")

	resp.Diagnostics.AddWarning(
		"Configuration Remains in Vault",
		fmt.Sprintf("The Kerberos auth backend configuration at '%s' has been removed from Terraform state, "+
			"but it may still exist in Vault unless the auth mount itself is deleted.", configPath),
	)
}

// ImportState handles resource import
func (r *kerberosAuthBackendConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	var mount string
	var err error

	// Parse the import ID using the official Vault API format
	mount, err = r.mountFromPath(id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID format",
			fmt.Sprintf("Expected format: 'auth/<mount>/config', got: '%s'", req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)

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

// configPath returns the Vault API path for Kerberos auth backend config
func (r *kerberosAuthBackendConfigResource) configPath(mount string) string {
	return fmt.Sprintf("auth/%s/config", mount)
}

// mountFromPath extracts the mount from the full path
func (r *kerberosAuthBackendConfigResource) mountFromPath(path string) (string, error) {
	if !kerberosConfigPathRegexp.MatchString(path) {
		return "", fmt.Errorf("no mount found in path: %s", path)
	}
	matches := kerberosConfigPathRegexp.FindStringSubmatch(path)
	if len(matches) != 2 {
		return "", fmt.Errorf("unexpected number of matches in path: %s", path)
	}
	return matches[1], nil
}

// getApiModel builds the Vault API request map from the Terraform data model.
func (r *kerberosAuthBackendConfigResource) getApiModel(config *kerberosAuthBackendConfigModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultRequest := map[string]any{
		consts.FieldKeytab:             config.KeytabWO.ValueString(),
		consts.FieldServiceAccount:     config.ServiceAccount.ValueString(),
		consts.FieldRemoveInstanceName: config.RemoveInstanceName.ValueBool(),
		consts.FieldAddGroupAliases:    config.AddGroupAliases.ValueBool(),
	}

	return vaultRequest, diags
}

// populateDataModelFromApi maps the Vault API response to the Terraform data model.
func (r *kerberosAuthBackendConfigResource) populateDataModelFromApi(config *kerberosAuthBackendConfigModel, respData map[string]interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	if respData == nil {
		diags.AddError("Missing data in API response", "The API response data was nil.")
		return diags
	}

	var apiModel kerberosAuthBackendConfigAPIModel
	if err := model.ToAPIModel(respData, &apiModel); err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return diags
	}

	config.ServiceAccount = types.StringValue(apiModel.ServiceAccount)

	if apiModel.RemoveInstanceName {
		config.RemoveInstanceName = types.BoolValue(apiModel.RemoveInstanceName)
	}
	if apiModel.AddGroupAliases {
		config.AddGroupAliases = types.BoolValue(apiModel.AddGroupAliases)
	}

	return diags
}
