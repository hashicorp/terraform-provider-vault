// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"
	"fmt"
	"os"

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
	"github.com/hashicorp/vault/api"
)

const (
	// ConfigGroupPolicyApplicationPath is the singleton resource path for Vault API and resource ID
	ConfigGroupPolicyApplicationPath = "sys/config/group-policy-application"

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
	base.BaseModel

	ID                         types.String `tfsdk:"id"`
	GroupPolicyApplicationMode types.String `tfsdk:"group_policy_application_mode"`
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
				MarkdownDescription: "The resource ID (always \"sys/config/group-policy-application\").",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldGroupPolicyApplicationMode: schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Mode for group policy application. Must be either \"within_namespace_hierarchy\" or \"any\". " +
					"\"within_namespace_hierarchy\" means policies only apply when the token authorizing a request was created in the same namespace as the group, or a descendant namespace. " +
					"\"any\" means group policies apply to all members of a group, regardless of what namespace the request token came from.",
			},
		},
		MarkdownDescription: "Manages the global group policy application mode for Vault Enterprise. " +
			"This resource controls how ACL policies attached to identity groups are applied across namespace boundaries. " +
			"**Important:** This is a singleton resource - only one instance per Vault cluster. " +
			"Must be managed from root or administrative namespace. " +
			"This configuration will be replicated between primary and secondaries - primaries cannot have a different policy application mode than secondaries.",
	}

	base.MustAddBaseSchema(&resp.Schema)
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

	_, err := vaultClient.Logical().WriteWithContext(ctx, ConfigGroupPolicyApplicationPath, vaultRequest)
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

	// Get namespace from plan data, default to root if not specified
	namespace := data.Namespace.ValueString()

	// Get Vault client
	vaultClient, ok := r.getClientForNamespace(ctx, namespace, &resp.Diagnostics)
	if !ok {
		return
	}

	mode := data.GroupPolicyApplicationMode.ValueString()

	// Write configuration to Vault
	if !r.writeGroupPolicyConfig(ctx, vaultClient, mode, &resp.Diagnostics, errutil.VaultCreateErr) {
		return
	}

	// Set the singleton ID
	data.ID = types.StringValue(ConfigGroupPolicyApplicationPath)

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

	namespace := data.Namespace.ValueString()

	// Get Vault client
	vaultClient, ok := r.getClientForNamespace(ctx, namespace, &resp.Diagnostics)
	if !ok {
		return
	}

	configResp, err := vaultClient.Logical().ReadWithContext(ctx, ConfigGroupPolicyApplicationPath)
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
			fmt.Sprintf("Missing %q in response for %q", consts.FieldGroupPolicyApplicationMode, ConfigGroupPolicyApplicationPath),
		)
		return
	}

	modeStr, ok := modeRaw.(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Invalid Vault API response",
			fmt.Sprintf("Expected %q to be a string in response for %q, got %T", consts.FieldGroupPolicyApplicationMode, ConfigGroupPolicyApplicationPath, modeRaw),
		)
		return
	}
	data.GroupPolicyApplicationMode = types.StringValue(modeStr)

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

	namespace := data.Namespace.ValueString()

	// Get Vault client
	vaultClient, ok := r.getClientForNamespace(ctx, namespace, &resp.Diagnostics)
	if !ok {
		return
	}

	mode := data.GroupPolicyApplicationMode.ValueString()

	// Write configuration to Vault
	if !r.writeGroupPolicyConfig(ctx, vaultClient, mode, &resp.Diagnostics, errutil.VaultUpdateErr) {
		return
	}

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

	namespace := data.Namespace.ValueString()

	// Get Vault client
	vaultClient, ok := r.getClientForNamespace(ctx, namespace, &resp.Diagnostics)
	if !ok {
		return
	}

	// Reset to default value instead of deleting
	if !r.writeGroupPolicyConfig(ctx, vaultClient, modeWithinNamespaceHierarchy, &resp.Diagnostics, errutil.VaultDeleteErr) {
		return
	}

	// Add a warning that the resource is being reset to default, not actually deleted
	resp.Diagnostics.AddWarning(
		"Resource Reset to Default",
		"The group policy application configuration cannot be deleted from Vault. "+
			"Instead, it has been reset to the default mode (within_namespace_hierarchy). "+
			"The resource will be removed from Terraform state, but the configuration remains in Vault with default settings.",
	)

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState implements the import functionality for this resource
func (r *ConfigGroupPolicyApplicationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should always be the full path
	if req.ID != ConfigGroupPolicyApplicationPath {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Import ID must be %q, got: %q", ConfigGroupPolicyApplicationPath, req.ID),
		)
		return
	}

	// Set the ID attribute
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldID), ConfigGroupPolicyApplicationPath)...)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), types.StringNull())...)

	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}
