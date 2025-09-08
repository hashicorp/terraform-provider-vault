// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &PasswordPolicyResource{}

// NewPasswordPolicyResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewPasswordPolicyResource() resource.Resource {
	return &PasswordPolicyResource{}
}

// PasswordPolicyResource implements the methods that define this resource
type PasswordPolicyResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// PasswordPolicyModel describes the Terraform resource data model to match the
// resource schema.
type PasswordPolicyModel struct {
	// common fields to all migrated resources
	base.BaseModelLegacy

	// fields specific to this resource
	Name   types.String `tfsdk:"name"`
	Policy types.String `tfsdk:"policy"`
}

// PasswordPolicyAPIModel describes the Vault API data model.
type PasswordPolicyAPIModel struct {
	Policy string `json:"policy" mapstructure:"policy"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#metadata-method
func (r *PasswordPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_password_policy"
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *PasswordPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of the password policy.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"policy": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The password policy document",
			},
		},
		MarkdownDescription: "Provides a resource to manage Password Policies.",
	}

	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/create
func (r *PasswordPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PasswordPolicyModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest := map[string]interface{}{
		"policy": data.Policy.ValueString(),
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

	// write the ID to state which is required for backwards compatibility
	data.ID = types.StringValue(data.Name.ValueString())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform
// refresh commands.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/read
func (r *PasswordPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PasswordPolicyModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
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
	policyResp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)

		return
	}
	if policyResp == nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadResponseNil(),
		)

		return
	}

	var readResp PasswordPolicyAPIModel
	err = model.ToAPIModel(policyResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.Policy = types.StringValue(readResp.Policy)

	// write the name to state to support the import command
	data.Name = types.StringValue(name)

	// write the ID to state which is required for backwards compatibility
	data.ID = types.StringValue(name)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/update
func (r *PasswordPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PasswordPolicyModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest := map[string]interface{}{
		"policy": data.Policy.ValueString(),
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

	// write the ID to state which is required for backwards compatibility
	data.ID = types.StringValue(data.Name.ValueString())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform apply command
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/delete
func (r *PasswordPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PasswordPolicyModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
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
		resp.Diagnostics.AddError(
			errutil.VaultDeleteErr(err),
		)

		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

func (r *PasswordPolicyResource) path(name string) string {
	return fmt.Sprintf("/sys/policies/password/%s", name)
}
