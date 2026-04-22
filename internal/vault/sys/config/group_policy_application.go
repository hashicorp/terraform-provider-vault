// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/api"
)

const (
	// Singleton resource ID
	configGroupPolicyApplicationID = "config"

	// Valid modes
	modeWithinNamespaceHierarchy = "within_namespace_hierarchy"
	modeAny                      = "any"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &ConfigGroupPolicyApplicationResource{}

// NewConfigGroupPolicyApplicationResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewConfigGroupPolicyApplicationResource() resource.Resource {
	return &ConfigGroupPolicyApplicationResource{}
}

// ConfigGroupPolicyApplicationResource implements the methods that define this resource
type ConfigGroupPolicyApplicationResource struct {
	base.ResourceWithConfigure
}

// ConfigGroupPolicyApplicationModel describes the Terraform resource data model to match the
// resource schema.
type ConfigGroupPolicyApplicationModel struct {
	ID                         types.String `tfsdk:"id"`
	GroupPolicyApplicationMode types.String `tfsdk:"group_policy_application_mode"`
	Namespace                  types.String `tfsdk:"namespace"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#metadata-method
func (r *ConfigGroupPolicyApplicationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_config_group_policy_application"
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *ConfigGroupPolicyApplicationResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldID: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The resource ID (always \"config\").",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldGroupPolicyApplicationMode: schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Mode for group policy application. Must be either \"within_namespace_hierarchy\" or \"any\". " +
					"Defaults to \"within_namespace_hierarchy\". " +
					"\"within_namespace_hierarchy\" means policies only apply when the token authorizing a request was created in the same namespace as the group, or a descendant namespace. " +
					"\"any\" means group policies apply to all members of a group, regardless of what namespace the request token came from.",
				Default: stringdefault.StaticString(modeWithinNamespaceHierarchy),
				Validators: []validator.String{
					stringvalidator.OneOf(modeWithinNamespaceHierarchy, modeAny),
				},
			},
			consts.FieldNamespace: schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Target namespace. Must be root (\"\") or administrative (\"admin\") namespace. Defaults to root namespace.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("", "admin"),
				},
			},
		},
		MarkdownDescription: "Manages the global group policy application mode for Vault Enterprise. " +
			"This resource controls how policies attached to identity groups are applied across namespace boundaries. " +
			"**Important:** This is a singleton resource - only one instance per Vault cluster. " +
			"Must be managed from root or administrative namespace. " +
			"Requires Vault Enterprise 1.13.8+.",
	}
}

// validateActualNamespace ensures the actual namespace from the client is root or administrative
func (r *ConfigGroupPolicyApplicationResource) validateActualNamespace(actualNamespace string, diagnostics *diag.Diagnostics) bool {
	if actualNamespace != "" && actualNamespace != "admin" {
		diagnostics.AddError(
			"Invalid Namespace",
			fmt.Sprintf("Group policy application configuration must be managed from the root "+
				"or administrative namespace. Current namespace: %q. "+
				"Please use namespace = \"\" (root) or namespace = \"admin\".", actualNamespace),
		)
		return false
	}
	return true
}

// validateEnterpriseAndVersion checks if the feature is supported in the current Vault version
func (r *ConfigGroupPolicyApplicationResource) validateEnterpriseAndVersion(diagnostics *diag.Diagnostics) bool {
	// Enterprise check
	if !provider.IsEnterpriseSupported(r.Meta()) {
		diagnostics.AddError(
			"Enterprise Feature Required",
			"Group policy application configuration is only available in Vault Enterprise.",
		)
		return false
	}

	// Version check
	if !provider.IsAPISupported(r.Meta(), provider.VaultVersion1138) {
		diagnostics.AddError(
			"Feature Not Supported",
			"Group policy application configuration requires Vault version 1.13.8 or later.",
		)
		return false
	}

	return true
}

// getClientForNamespace initializes and returns a Vault client for the specified namespace
func (r *ConfigGroupPolicyApplicationResource) getClientForNamespace(ctx context.Context, namespace string, diagnostics *diag.Diagnostics) (*api.Client, bool) {
	vaultClient, err := client.GetClient(ctx, r.Meta(), namespace)
	if err != nil {
		diagnostics.AddError(errutil.ClientConfigureErr(err))
		return nil, false
	}
	return vaultClient, true
}

// writeGroupPolicyConfig writes the group policy application mode to Vault
func (r *ConfigGroupPolicyApplicationResource) writeGroupPolicyConfig(ctx context.Context, vaultClient *api.Client, mode string, diagnostics *diag.Diagnostics, errorFunc func(error) (string, string)) bool {
	vaultRequest := map[string]interface{}{
		consts.FieldGroupPolicyApplicationMode: mode,
	}

	endpointPath := r.path()
	_, err := vaultClient.Logical().WriteWithContext(ctx, endpointPath, vaultRequest)
	if err != nil {
		diagnostics.AddError(errorFunc(err))
		return false
	}
	return true
}

// Create is called during the terraform apply command.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/create
func (r *ConfigGroupPolicyApplicationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConfigGroupPolicyApplicationModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Validate enterprise and version requirements
	if !r.validateEnterpriseAndVersion(&resp.Diagnostics) {
		return
	}

	// Get namespace from plan data, default to root if not specified
	namespace := data.Namespace.ValueString()

	// Get Vault client
	vaultClient, ok := r.getClientForNamespace(ctx, namespace, &resp.Diagnostics)
	if !ok {
		return
	}

	// Get the actual namespace from the client
	actualNamespace := vaultClient.Namespace()

	// Validate actual namespace - must be root or administrative
	if !r.validateActualNamespace(actualNamespace, &resp.Diagnostics) {
		return
	}

	mode := data.GroupPolicyApplicationMode.ValueString()

	// Write configuration to Vault
	if !r.writeGroupPolicyConfig(ctx, vaultClient, mode, &resp.Diagnostics, errutil.VaultCreateErr) {
		return
	}

	// Set the singleton ID
	data.ID = types.StringValue(configGroupPolicyApplicationID)

	// Set namespace to the actual namespace from the client
	data.Namespace = types.StringValue(actualNamespace)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform
// refresh commands.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/read
func (r *ConfigGroupPolicyApplicationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConfigGroupPolicyApplicationModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Validate enterprise and version requirements
	if !r.validateEnterpriseAndVersion(&resp.Diagnostics) {
		return
	}

	namespace := data.Namespace.ValueString()

	// Get Vault client
	vaultClient, ok := r.getClientForNamespace(ctx, namespace, &resp.Diagnostics)
	if !ok {
		return
	}

	// Get the actual namespace from the client
	actualNamespace := vaultClient.Namespace()

	// Validate actual namespace - must be root or administrative
	if !r.validateActualNamespace(actualNamespace, &resp.Diagnostics) {
		return
	}

	endpointPath := r.path()
	configResp, err := vaultClient.Logical().ReadWithContext(ctx, endpointPath)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)
		return
	}
	// If response is nil, the configuration has been deleted outside of Terraform
	if configResp == nil || configResp.Data == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Extract mode from response
	modeRaw, ok := configResp.Data[consts.FieldGroupPolicyApplicationMode]
	if !ok {
		resp.Diagnostics.AddError(
			"Invalid Vault API response",
			fmt.Sprintf("Missing %q in response for %q", consts.FieldGroupPolicyApplicationMode, endpointPath),
		)
		return
	}

	modeStr, ok := modeRaw.(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Invalid Vault API response",
			fmt.Sprintf("Expected %q to be a string in response for %q, got %T", consts.FieldGroupPolicyApplicationMode, endpointPath, modeRaw),
		)
		return
	}
	data.GroupPolicyApplicationMode = types.StringValue(modeStr)

	// Always set namespace explicitly (it's computed)
	data.Namespace = types.StringValue(actualNamespace)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/update
func (r *ConfigGroupPolicyApplicationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConfigGroupPolicyApplicationModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Validate enterprise and version requirements
	if !r.validateEnterpriseAndVersion(&resp.Diagnostics) {
		return
	}

	namespace := data.Namespace.ValueString()

	// Get Vault client
	vaultClient, ok := r.getClientForNamespace(ctx, namespace, &resp.Diagnostics)
	if !ok {
		return
	}

	// Get the actual namespace from the client
	actualNamespace := vaultClient.Namespace()

	// Validate actual namespace - must be root or administrative
	if !r.validateActualNamespace(actualNamespace, &resp.Diagnostics) {
		return
	}

	mode := data.GroupPolicyApplicationMode.ValueString()

	// Write configuration to Vault
	if !r.writeGroupPolicyConfig(ctx, vaultClient, mode, &resp.Diagnostics, errutil.VaultUpdateErr) {
		return
	}

	// Always set namespace explicitly (it's computed)
	data.Namespace = types.StringValue(actualNamespace)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform apply command
// For this singleton resource, delete resets to the default value
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/delete
func (r *ConfigGroupPolicyApplicationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConfigGroupPolicyApplicationModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Validate enterprise and version requirements
	if !r.validateEnterpriseAndVersion(&resp.Diagnostics) {
		return
	}

	namespace := data.Namespace.ValueString()

	// Get Vault client
	vaultClient, ok := r.getClientForNamespace(ctx, namespace, &resp.Diagnostics)
	if !ok {
		return
	}

	// Get the actual namespace from the client
	actualNamespace := vaultClient.Namespace()

	// Validate actual namespace - must be root or administrative
	if !r.validateActualNamespace(actualNamespace, &resp.Diagnostics) {
		return
	}

	// Reset to default value instead of deleting
	if !r.writeGroupPolicyConfig(ctx, vaultClient, modeWithinNamespaceHierarchy, &resp.Diagnostics, errutil.VaultUpdateErr) {
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState implements the import functionality for this resource
func (r *ConfigGroupPolicyApplicationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should always be "config"
	if req.ID != configGroupPolicyApplicationID {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Import ID must be %q, got: %q", configGroupPolicyApplicationID, req.ID),
		)
		return
	}

	// Set the ID attribute
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldID), configGroupPolicyApplicationID)...)

	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
		return
	}

	// Set namespace to root by default
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), "")...)
}

func (r *ConfigGroupPolicyApplicationResource) path() string {
	return "sys/config/group-policy-application"
}
