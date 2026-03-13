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
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
)

var (
	// Regex patterns for parsing import path
	kerberosAuthBackendGroupMountFromPathRegex = regexp.MustCompile("^auth/(.+)/groups/.+$")
	kerberosAuthBackendGroupNameFromPathRegex  = regexp.MustCompile("^auth/.+/groups/(.+)$")
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &kerberosAuthBackendGroupResource{}

// NewKerberosAuthBackendGroupResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewKerberosAuthBackendGroupResource() resource.Resource {
	return &kerberosAuthBackendGroupResource{}
}

// kerberosAuthBackendGroupResource implements the methods that define this resource
type kerberosAuthBackendGroupResource struct {
	base.ResourceWithConfigure
}

// kerberosAuthBackendGroupModel describes the Terraform resource data model to match the
// resource schema.
type kerberosAuthBackendGroupModel struct {
	base.BaseModel

	Mount    types.String `tfsdk:"mount"`
	Name     types.String `tfsdk:"name"`
	Policies types.Set    `tfsdk:"policies"`
}

// kerberosAuthBackendGroupAPIModel describes the Vault API response structure.
type kerberosAuthBackendGroupAPIModel struct {
	Policies []string `json:"policies" mapstructure:"policies"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
func (r *kerberosAuthBackendGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kerberos_auth_backend_group"
}

// Schema defines this resource's schema
func (r *kerberosAuthBackendGroupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path where the Kerberos auth method is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					validators.PathValidator(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "The name of the LDAP group.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldPolicies: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Set of Vault policies to associate with this group.",
				Optional:            true,
			},
		},
		MarkdownDescription: "Manages LDAP group to Vault policy mappings for the Kerberos authentication method.",
	}

	// Add the common base schema
	base.MustAddBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *kerberosAuthBackendGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data kerberosAuthBackendGroupModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write group to Vault and read back
	resp.Diagnostics.Append(r.writeGroup(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *kerberosAuthBackendGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data kerberosAuthBackendGroupModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read group from Vault
	found, readDiags := r.readGroup(ctx, &data)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If not found, remove from state
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command.
func (r *kerberosAuthBackendGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data kerberosAuthBackendGroupModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write group to Vault and read back
	resp.Diagnostics.Append(r.writeGroup(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform destroy command.
func (r *kerberosAuthBackendGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data kerberosAuthBackendGroupModel

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

	mount := strings.Trim(data.Mount.ValueString(), "/")
	name := strings.Trim(data.Name.ValueString(), "/")
	groupPath := r.groupPath(mount, name)

	tflog.Debug(ctx, fmt.Sprintf("Deleting Kerberos group at '%s'", groupPath))
	_, err = vaultClient.Logical().DeleteWithContext(ctx, groupPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting Kerberos group",
			fmt.Sprintf("Could not delete Kerberos group at '%s': %s", groupPath, err),
		)
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Deleted Kerberos group at '%s'", groupPath))
}

// writeGroup is a reusable helper that writes a group to Vault and reads it back.
// Used by both Create and Update operations.
func (r *kerberosAuthBackendGroupResource) writeGroup(ctx context.Context, data *kerberosAuthBackendGroupModel) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return diags
	}

	mount := strings.Trim(data.Mount.ValueString(), "/")
	name := strings.Trim(data.Name.ValueString(), "/")
	groupPath := r.groupPath(mount, name)

	// Build the API request
	vaultRequest, apiDiags := r.getApiModel(ctx, data)
	diags.Append(apiDiags...)
	if diags.HasError() {
		return diags
	}

	// Write group to Vault
	tflog.Debug(ctx, fmt.Sprintf("Writing Kerberos group to '%s'", groupPath))
	_, err = vaultClient.Logical().WriteWithContext(ctx, groupPath, vaultRequest)
	if err != nil {
		diags.AddError(
			"Error writing Kerberos group",
			fmt.Sprintf("Could not write Kerberos group to '%s': %s", groupPath, err),
		)
		return diags
	}
	tflog.Info(ctx, fmt.Sprintf("Kerberos group successfully written to '%s'", groupPath))

	// Read back group from Vault to populate computed fields using readGroup
	found, readDiags := r.readGroup(ctx, data)
	diags.Append(readDiags...)
	if diags.HasError() {
		return diags
	}
	if !found {
		diags.AddError(
			"Error reading back Kerberos group after write",
			fmt.Sprintf("Group at '%s' was not found after successful write", groupPath),
		)
		return diags
	}

	return diags
}

// readGroup is a reusable helper that reads a group from Vault.
// Returns true if the group was found, false if not found.
// Used by the Read operation.
func (r *kerberosAuthBackendGroupResource) readGroup(ctx context.Context, data *kerberosAuthBackendGroupModel) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return false, diags
	}

	mount := strings.Trim(data.Mount.ValueString(), "/")
	name := strings.Trim(data.Name.ValueString(), "/")
	groupPath := r.groupPath(mount, name)

	// Read group from Vault
	tflog.Debug(ctx, fmt.Sprintf("Reading Kerberos group from '%s'", groupPath))
	groupResp, err := vaultClient.Logical().ReadWithContext(ctx, groupPath)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return false, diags
	}
	if groupResp == nil {
		tflog.Warn(ctx, fmt.Sprintf("Kerberos group at '%s' not found, removing from state", groupPath))
		return false, diags
	}

	// Populate model from API response
	populateDiags := r.populateDataModelFromApi(ctx, data, groupResp.Data)
	diags.Append(populateDiags...)
	return true, diags
}

// ImportState handles resource import
func (r *kerberosAuthBackendGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	var mount, name string
	var err error

	// Parse the import ID using the official Vault API format
	mount, err = r.mountFromPath(id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID format",
			fmt.Sprintf("Expected format: 'auth/<mount>/groups/<name>', got: '%s'", req.ID),
		)
		return
	}

	name, err = r.nameFromPath(id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID format",
			fmt.Sprintf("Could not parse group name from path '%s': %s", id, err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)

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

// groupPath returns the Vault API path for Kerberos group
func (r *kerberosAuthBackendGroupResource) groupPath(mount, name string) string {
	return fmt.Sprintf("auth/%s/groups/%s", mount, name)
}

// mountFromPath extracts the mount from the full path
func (r *kerberosAuthBackendGroupResource) mountFromPath(path string) (string, error) {
	if !kerberosAuthBackendGroupMountFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no mount found in path: %s", path)
	}
	matches := kerberosAuthBackendGroupMountFromPathRegex.FindStringSubmatch(path)
	if len(matches) != 2 {
		return "", fmt.Errorf("unexpected number of matches in path: %s", path)
	}
	return matches[1], nil
}

// nameFromPath extracts the group name from the full path
func (r *kerberosAuthBackendGroupResource) nameFromPath(path string) (string, error) {
	if !kerberosAuthBackendGroupNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no group name found in path: %s", path)
	}
	matches := kerberosAuthBackendGroupNameFromPathRegex.FindStringSubmatch(path)
	if len(matches) != 2 {
		return "", fmt.Errorf("unexpected number of matches in path: %s", path)
	}
	return matches[1], nil
}

// getApiModel builds the Vault API request map from the Terraform data model.
func (r *kerberosAuthBackendGroupResource) getApiModel(ctx context.Context, data *kerberosAuthBackendGroupModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	var policies []string
	diags.Append(data.Policies.ElementsAs(ctx, &policies, false)...)
	if diags.HasError() {
		return nil, diags
	}
	vaultRequest := map[string]any{
		consts.FieldPolicies: policies,
	}

	return vaultRequest, diags
}

// populateDataModelFromApi maps the Vault API response to the Terraform data model.
func (r *kerberosAuthBackendGroupResource) populateDataModelFromApi(ctx context.Context, data *kerberosAuthBackendGroupModel, respData map[string]any) diag.Diagnostics {
	var diags diag.Diagnostics

	if respData == nil {
		diags.AddError("Missing data in API response", "The API response data was nil.")
		return diags
	}

	// Decode API response into API model using model.ToAPIModel
	var apiModel kerberosAuthBackendGroupAPIModel
	if err := model.ToAPIModel(respData, &apiModel); err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return diags
	}

	// Convert policies from API model to Terraform model
	if len(apiModel.Policies) > 0 {
		policies, setDiags := types.SetValueFrom(ctx, types.StringType, apiModel.Policies)
		diags.Append(setDiags...)
		if diags.HasError() {
			return diags
		}
		data.Policies = policies
	}

	return diags
}
