// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &ConfigUIHeaderResource{}

// NewConfigUIHeaderResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewConfigUIHeaderResource() resource.Resource {
	return &ConfigUIHeaderResource{}
}

// ConfigUIHeaderResource implements the methods that define this resource
type ConfigUIHeaderResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// ConfigUIHeaderModel describes the Terraform resource data model to match the
// resource schema.
type ConfigUIHeaderModel struct {
	// common fields to all migrated resources
	base.BaseModelLegacy

	// fields specific to this resource
	Name   types.String `tfsdk:"name"`
	Values types.List   `tfsdk:"values"`
}

// ConfigUIHeaderAPIModel describes the Vault API data model for write operations.
type ConfigUIHeaderAPIModel struct {
	Values []string `json:"values" mapstructure:"values"`
}

// ConfigUIHeaderReadAPIModel describes the Vault API data model for read operations
// with multivalue=true parameter.
type ConfigUIHeaderReadAPIModel struct {
	Values []string `json:"values" mapstructure:"values"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#metadata-method
func (r *ConfigUIHeaderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_config_ui_header"
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *ConfigUIHeaderResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the custom header.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldValues: schema.ListAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "List of values for the header. At least one value is required.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
			},
		},
		MarkdownDescription: "Manages custom HTTP headers for the Vault UI.",
	}

	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/create
func (r *ConfigUIHeaderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConfigUIHeaderModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Check if Vault version supports UI headers (requires 1.16.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion116) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			"Custom UI headers require Vault version 1.16.0 or later. "+
				"Current Vault version: "+r.Meta().GetVaultVersion().String(),
		)
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Convert values list to string slice
	var values []string
	resp.Diagnostics.Append(data.Values.ElementsAs(ctx, &values, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultRequest := map[string]interface{}{
		consts.FieldValues: values,
	}

	path := r.path(data.Name.ValueString())
	// vault returns a nil response on success
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		// Provide helpful error message for sudo capability requirement
		if strings.Contains(err.Error(), "permission denied") {
			resp.Diagnostics.AddError(
				"Permission Denied",
				fmt.Sprintf("Error creating UI header %q: %s\n\n"+
					"This operation requires the 'sudo' capability. "+
					"Ensure your Vault policy includes:\n"+
					"path \"sys/config/ui/headers/*\" {\n"+
					"  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n"+
					"}",
					data.Name.ValueString(), err),
			)
		} else {
			resp.Diagnostics.AddError(
				errutil.VaultCreateErr(err),
			)
		}
		return
	}

	// Read back the created resource to populate state
	readPath := r.path(data.Name.ValueString())
	queryParams := map[string][]string{
		"multivalue": {"true"},
	}
	headerResp, err := client.Logical().ReadWithDataWithContext(ctx, readPath, queryParams)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)
		return
	}
	if headerResp == nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadResponseNil(),
		)
		return
	}

	var readResp ConfigUIHeaderReadAPIModel
	err = model.ToAPIModel(headerResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Convert values slice to types.List
	valuesList, diags := types.ListValueFrom(ctx, types.StringType, readResp.Values)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Values = valuesList

	// write the ID to state which is required for backwards compatibility
	data.ID = types.StringValue(data.Name.ValueString())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform
// refresh commands.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/read
func (r *ConfigUIHeaderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConfigUIHeaderModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Check if Vault version supports UI headers (requires 1.16.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion116) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			"Custom UI headers require Vault version 1.16.0 or later. "+
				"Current Vault version: "+r.Meta().GetVaultVersion().String(),
		)
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// read the name from the id field to support the import command
	name := data.ID.ValueString()
	path := r.path(name)
	// Use multivalue=true parameter to get consistent response format
	queryParams := map[string][]string{
		"multivalue": {"true"},
	}
	headerResp, err := client.Logical().ReadWithDataWithContext(ctx, path, queryParams)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)
		return
	}
	if headerResp == nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadResponseNil(),
		)
		return
	}

	var readResp ConfigUIHeaderReadAPIModel
	err = model.ToAPIModel(headerResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Convert values slice to types.List
	valuesList, diags := types.ListValueFrom(ctx, types.StringType, readResp.Values)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Values = valuesList

	// write the name to state to support the import command
	data.Name = types.StringValue(name)

	// write the ID to state which is required for backwards compatibility
	data.ID = types.StringValue(name)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/update
func (r *ConfigUIHeaderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConfigUIHeaderModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Check if Vault version supports UI headers (requires 1.16.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion116) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			"Custom UI headers require Vault version 1.16.0 or later. "+
				"Current Vault version: "+r.Meta().GetVaultVersion().String(),
		)
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Convert values list to string slice
	var values []string
	resp.Diagnostics.Append(data.Values.ElementsAs(ctx, &values, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultRequest := map[string]interface{}{
		consts.FieldValues: values,
	}

	path := r.path(data.Name.ValueString())
	// vault returns a nil response on success
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		// Provide helpful error message for sudo capability requirement
		if strings.Contains(err.Error(), "permission denied") {
			resp.Diagnostics.AddError(
				"Permission Denied",
				fmt.Sprintf("Error updating UI header %q: %s\n\n"+
					"This operation requires the 'sudo' capability. "+
					"Ensure your Vault policy includes:\n"+
					"path \"sys/config/ui/headers/*\" {\n"+
					"  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n"+
					"}",
					data.Name.ValueString(), err),
			)
		} else {
			resp.Diagnostics.AddError(
				errutil.VaultUpdateErr(err),
			)
		}
		return
	}

	// Read back the updated resource to populate state
	readPath := r.path(data.Name.ValueString())
	queryParams := map[string][]string{
		"multivalue": {"true"},
	}
	headerResp, err := client.Logical().ReadWithDataWithContext(ctx, readPath, queryParams)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)
		return
	}
	if headerResp == nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadResponseNil(),
		)
		return
	}

	var readResp ConfigUIHeaderReadAPIModel
	err = model.ToAPIModel(headerResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Convert values slice to types.List
	valuesList, diags := types.ListValueFrom(ctx, types.StringType, readResp.Values)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Values = valuesList

	// write the ID to state which is required for backwards compatibility
	data.ID = types.StringValue(data.Name.ValueString())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform apply command
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/delete
func (r *ConfigUIHeaderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConfigUIHeaderModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Check if Vault version supports UI headers (requires 1.16.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion116) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			"Custom UI headers require Vault version 1.16.0 or later. "+
				"Current Vault version: "+r.Meta().GetVaultVersion().String(),
		)
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := r.path(data.Name.ValueString())

	_, err = client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		// Provide helpful error message for sudo capability requirement
		if strings.Contains(err.Error(), "permission denied") {
			resp.Diagnostics.AddError(
				"Permission Denied",
				fmt.Sprintf("Error deleting UI header %q: %s\n\n"+
					"This operation requires the 'sudo' capability. "+
					"Ensure your Vault policy includes:\n"+
					"path \"sys/config/ui/headers/*\" {\n"+
					"  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n"+
					"}",
					data.Name.ValueString(), err),
			)
		} else {
			resp.Diagnostics.AddError(
				errutil.VaultDeleteErr(err),
			)
		}
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

func (r *ConfigUIHeaderResource) path(name string) string {
	return fmt.Sprintf("sys/config/ui/headers/%s", name)
}
