// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &ConfigUIDefaultAuthResource{}

// NewConfigUIDefaultAuthResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewConfigUIDefaultAuthResource() resource.Resource {
	return &ConfigUIDefaultAuthResource{}
}

// ConfigUIDefaultAuthResource implements the methods that define this resource
type ConfigUIDefaultAuthResource struct {
	base.ResourceWithConfigure
}

// ConfigUIDefaultAuthModel describes the Terraform resource data model to match the
// resource schema.
type ConfigUIDefaultAuthModel struct {
	// common fields to all migrated resources
	base.BaseModel

	// fields specific to this resource
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	NamespacePath      types.String `tfsdk:"namespace_path"`
	DefaultAuthType    types.String `tfsdk:"default_auth_type"`
	BackupAuthTypes    types.List   `tfsdk:"backup_auth_types"`
	DisableInheritance types.Bool   `tfsdk:"disable_inheritance"`
}

// ConfigUIDefaultAuthAPIModel describes the Vault API data model.
type ConfigUIDefaultAuthAPIModel struct {
	DefaultAuthType    string   `json:"default_auth_type" mapstructure:"default_auth_type"`
	BackupAuthTypes    []string `json:"backup_auth_types" mapstructure:"backup_auth_types"`
	DisableInheritance bool     `json:"disable_inheritance" mapstructure:"disable_inheritance"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#metadata-method
func (r *ConfigUIDefaultAuthResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_config_ui_default_auth"
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *ConfigUIDefaultAuthResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldID: schema.StringAttribute{
				MarkdownDescription: "The unique identifier for this resource.",
				Computed:            true,
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Unique identifier for the configuration. Can contain letters, numbers, underscores, and dashes. Uses `RequiresReplace()` plan modifier - changing this forces resource recreation.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldNamespacePath: schema.StringAttribute{
				MarkdownDescription: "Target namespace for the configuration. Empty string or omitted applies to root namespace.",
				Optional:            true,
			},
			consts.FieldDefaultAuthType: schema.StringAttribute{
				MarkdownDescription: "The default authentication method. Uses `OneOf` validator to ensure only valid auth methods are accepted: github, jwt, ldap, oidc, okta, radius, saml, token, userpass.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"github",
						"jwt",
						"ldap",
						"oidc",
						"okta",
						"radius",
						"saml",
						"token",
						"userpass",
					),
				},
			},
			consts.FieldBackupAuthTypes: schema.ListAttribute{
				MarkdownDescription: "List of backup authentication methods. Uses `ListAttribute` with `ElementType: StringType` to preserve order of backup methods. Each must be a valid auth type. Vault presents these in the \"Sign in with other methods\" tab.",
				ElementType:         types.StringType,
				Optional:            true,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf(
							"github",
							"jwt",
							"ldap",
							"oidc",
							"okta",
							"radius",
							"saml",
							"token",
							"userpass",
						),
					),
				},
			},
			consts.FieldDisableInheritance: schema.BoolAttribute{
				MarkdownDescription: "If true, child namespaces will not inherit default_auth_type and backup_auth_types from this configuration.",
				Optional:            true,
			},
		},
		MarkdownDescription: "Manages the UI default authentication configuration for the Vault GUI login form. This is an Enterprise-only feature requiring Vault 1.20.0 or later.",
	}

	base.MustAddBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/create
func (r *ConfigUIDefaultAuthResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConfigUIDefaultAuthModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Enterprise check
	if !provider.IsEnterpriseSupported(r.Meta()) {
		resp.Diagnostics.AddError(
			"Enterprise Feature",
			"vault_config_ui_default_auth requires Vault Enterprise",
		)
		return
	}

	// Version check
	if !provider.IsAPISupported(r.Meta(), provider.VaultVersion120) {
		resp.Diagnostics.AddError(
			"Unsupported Vault Version",
			"vault_config_ui_default_auth requires Vault 1.20.0 or later",
		)
		return
	}

	// This endpoint must be called from root or administrative namespace
	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest := map[string]interface{}{
		consts.FieldDefaultAuthType: data.DefaultAuthType.ValueString(),
	}

	// Always include namespace_path
	// Normalize: empty string or "root" becomes "root/" for the API
	namespacePath := ""
	if !data.NamespacePath.IsNull() && !data.NamespacePath.IsUnknown() {
		namespacePath = data.NamespacePath.ValueString()
	}
	if namespacePath == "" || namespacePath == "root" {
		namespacePath = "root/"
	}
	vaultRequest[consts.FieldNamespacePath] = namespacePath

	// Add backup_auth_types if provided
	if !data.BackupAuthTypes.IsNull() && !data.BackupAuthTypes.IsUnknown() {
		var backupAuthTypes []string
		resp.Diagnostics.Append(data.BackupAuthTypes.ElementsAs(ctx, &backupAuthTypes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		vaultRequest[consts.FieldBackupAuthTypes] = backupAuthTypes
	}

	// Add disable_inheritance if provided
	if !data.DisableInheritance.IsNull() && !data.DisableInheritance.IsUnknown() {
		vaultRequest[consts.FieldDisableInheritance] = data.DisableInheritance.ValueBool()
	}

	path := r.path(data.Name.ValueString())
	// vault returns a nil response on success
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultCreateErr(err),
		)

		return
	}

	// Set the ID to the name value
	data.ID = data.Name

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform
// refresh commands.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/read
func (r *ConfigUIDefaultAuthResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConfigUIDefaultAuthModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// This endpoint must be called from root or administrative namespace
	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// read the name from the name field to support the import command
	name := data.Name.ValueString()
	path := r.path(name)
	configResp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)

		return
	}
	if configResp == nil {
		// Resource has been deleted outside of Terraform, remove from state
		resp.State.RemoveResource(ctx)
		return
	}

	var readResp ConfigUIDefaultAuthAPIModel
	err = model.ToAPIModel(configResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.DefaultAuthType = types.StringValue(readResp.DefaultAuthType)

	// Handle namespace_path - normalize "root/" to empty string to match Terraform config
	if namespacePath, ok := configResp.Data[consts.FieldNamespacePath].(string); ok {
		// Normalize root namespace to empty string
		if namespacePath == "root/" {
			namespacePath = ""
		} else {
			namespacePath = strings.TrimSuffix(namespacePath, "/")
		}
		// Only set if not empty or if it was explicitly set in config
		if namespacePath != "" || !data.NamespacePath.IsNull() {
			data.NamespacePath = types.StringValue(namespacePath)
		}
	}

	// Handle backup_auth_types - only set if present in API response
	if len(readResp.BackupAuthTypes) > 0 {
		backupAuthTypes, diags := types.ListValueFrom(ctx, types.StringType, readResp.BackupAuthTypes)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.BackupAuthTypes = backupAuthTypes
	} else if !data.BackupAuthTypes.IsNull() {
		// If config had backup_auth_types but API returns empty, set to empty list
		emptyList, diags := types.ListValueFrom(ctx, types.StringType, []string{})
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			data.BackupAuthTypes = emptyList
		}
	}

	// Handle disable_inheritance - only set if it was in the config or if true
	if readResp.DisableInheritance {
		data.DisableInheritance = types.BoolValue(true)
	} else if !data.DisableInheritance.IsNull() {
		// If it was set in config, preserve the false value
		data.DisableInheritance = types.BoolValue(false)
	}

	// write the name to state to support the import command
	data.Name = types.StringValue(name)

	// Set the ID to the name value
	data.ID = data.Name

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/update
func (r *ConfigUIDefaultAuthResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConfigUIDefaultAuthModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// This endpoint must be called from root or administrative namespace
	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest := map[string]interface{}{
		consts.FieldDefaultAuthType: data.DefaultAuthType.ValueString(),
	}

	// Always include namespace_path
	// Normalize: empty string or "root" becomes "root/" for the API
	namespacePath := ""
	if !data.NamespacePath.IsNull() && !data.NamespacePath.IsUnknown() {
		namespacePath = data.NamespacePath.ValueString()
	}
	if namespacePath == "" || namespacePath == "root" {
		namespacePath = "root/"
	}
	vaultRequest[consts.FieldNamespacePath] = namespacePath

	// Add backup_auth_types if provided
	if !data.BackupAuthTypes.IsNull() && !data.BackupAuthTypes.IsUnknown() {
		var backupAuthTypes []string
		resp.Diagnostics.Append(data.BackupAuthTypes.ElementsAs(ctx, &backupAuthTypes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		vaultRequest[consts.FieldBackupAuthTypes] = backupAuthTypes
	}

	// Add disable_inheritance if provided
	if !data.DisableInheritance.IsNull() && !data.DisableInheritance.IsUnknown() {
		vaultRequest[consts.FieldDisableInheritance] = data.DisableInheritance.ValueBool()
	}

	path := r.path(data.Name.ValueString())
	// vault returns a nil response on success
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultUpdateErr(err),
		)

		return
	}

	// Set the ID to the name value
	data.ID = data.Name

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform apply command
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/delete
func (r *ConfigUIDefaultAuthResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConfigUIDefaultAuthModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// This endpoint must be called from root or administrative namespace
	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := r.path(data.Name.ValueString())

	_, err = client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultDeleteErr(err),
		)

		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState implements the import functionality for this resource
func (r *ConfigUIDefaultAuthResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID is the name of the config
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), req.ID)...)
	// Set the ID attribute to match the name
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldID), req.ID)...)

	// Handle namespace from environment variable for Enterprise
	// This is critical for proper resource management - without the namespace in state,
	// subsequent Delete/Update operations will target the wrong namespace and fail silently
	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

func (r *ConfigUIDefaultAuthResource) path(name string) string {
	return fmt.Sprintf("sys/config/ui/login/default-auth/%s", name)
}
