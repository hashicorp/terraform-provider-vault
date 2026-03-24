// Copyright (c) 2017 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &RotationPolicyResource{}

// NewRotationPolicyResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider.
func NewRotationPolicyResource() resource.Resource {
	return &RotationPolicyResource{}
}

// RotationPolicyResource implements the methods that define this resource.
type RotationPolicyResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// RotationPolicyModel describes the Terraform resource data model.
type RotationPolicyModel struct {
	// common fields to all migrated resources
	base.BaseModelLegacy

	// fields specific to this resource
	Name   types.String `tfsdk:"name"`
	Policy types.String `tfsdk:"policy"`
}

// Metadata defines the resource name as it would appear in Terraform configurations.
func (r *RotationPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rotation_policy"
}

// Schema defines this resource's schema.
func (r *RotationPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the rotation policy.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldPolicy: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "A JSON rotation policy document. Must be non-empty. See Vault documentation for policy semantics.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
		},
		MarkdownDescription: "Provides a resource to manage Rotation Policies.",
	}

	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *RotationPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RotationPolicyModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.isSupported(&resp.Diagnostics) {
		return
	}

	if strings.TrimSpace(data.Policy.ValueString()) == "" {
		resp.Diagnostics.AddError("Invalid rotation policy", "The policy field must not be empty.")
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest := map[string]interface{}{
		consts.FieldPolicy: data.Policy.ValueString(),
	}

	path := r.path(data.Name.ValueString())
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	data.ID = types.StringValue(data.Name.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *RotationPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RotationPolicyModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.isSupported(&resp.Diagnostics) {
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	name := data.ID.ValueString()
	path := r.path(name)
	policyResp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if policyResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	policy, err := extractRotationPolicy(policyResp.Data)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.Name = types.StringValue(name)
	data.ID = types.StringValue(name)
	data.Policy = types.StringValue(policy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command.
func (r *RotationPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data RotationPolicyModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.isSupported(&resp.Diagnostics) {
		return
	}

	if strings.TrimSpace(data.Policy.ValueString()) == "" {
		resp.Diagnostics.AddError("Invalid rotation policy", "The policy field must not be empty.")
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest := map[string]interface{}{
		consts.FieldPolicy: data.Policy.ValueString(),
	}

	path := r.path(data.Name.ValueString())
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	data.ID = types.StringValue(data.Name.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform apply command.
func (r *RotationPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RotationPolicyModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.isSupported(&resp.Diagnostics) {
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
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *RotationPolicyResource) path(name string) string {
	return fmt.Sprintf("/sys/policies/rotation/%s", name)
}

func (r *RotationPolicyResource) isSupported(diags *diag.Diagnostics) bool {
	if !provider.IsEnterpriseSupported(r.Meta()) {
		diags.AddError("Unsupported Vault edition", "The vault_rotation_policy resource requires Vault Enterprise.")
		return false
	}

	if !provider.IsAPISupported(r.Meta(), provider.VaultVersion200) {
		diags.AddError("Unsupported Vault version", "The vault_rotation_policy resource requires Vault 2.0.0 or newer.")
		return false
	}

	return true
}

func extractRotationPolicy(data map[string]interface{}) (string, error) {
	if raw, ok := data[consts.FieldPolicy]; ok {
		switch v := raw.(type) {
		case string:
			return v, nil
		default:
			buf, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(buf), nil
		}
	}

	buf, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}
