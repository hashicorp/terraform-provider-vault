// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &ApproleAuthBackendRoleSecretIDEphemeralResource{}

// NewApproleAuthBackendRoleSecretIDEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewApproleAuthBackendRoleSecretIDEphemeralResource = func() ephemeral.EphemeralResource {
	return &ApproleAuthBackendRoleSecretIDEphemeralResource{}
}

// ApproleAuthBackendRoleSecretIDEphemeralResource implements the methods that define this resource
type ApproleAuthBackendRoleSecretIDEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// ApproleAuthBackendRoleSecretIDEphemeralModel describes the Terraform resource data model to match the
// resource schema.
type ApproleAuthBackendRoleSecretIDEphemeralModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Backend  types.String `tfsdk:"backend"`
	RoleName types.String `tfsdk:"role_name"`
	CIDRList types.Set    `tfsdk:"cidr_list"`
	Metadata types.String `tfsdk:"metadata"`
	TTL      types.Int64  `tfsdk:"ttl"`
	NumUses  types.Int64  `tfsdk:"num_uses"`
	SecretID types.String `tfsdk:"secret_id"`
	Accessor types.String `tfsdk:"accessor"`
}

// ApproleAuthBackendRoleSecretIDAPIModel describes the Vault API data model.
type ApproleAuthBackendRoleSecretIDAPIModel struct {
	SecretID         string `json:"secret_id" mapstructure:"secret_id"`
	SecretIDAccessor string `json:"secret_id_accessor" mapstructure:"secret_id_accessor"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *ApproleAuthBackendRoleSecretIDEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "Unique name of the auth backend to configure.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldRoleName: schema.StringAttribute{
				MarkdownDescription: "Name of the role.",
				Required:            true,
			},
			consts.FieldCIDRList: schema.SetAttribute{
				MarkdownDescription: "List of CIDR blocks that can log in using the SecretID.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			consts.FieldMetadata: schema.StringAttribute{
				MarkdownDescription: "JSON-encoded secret data.",
				Optional:            true,
			},
			consts.FieldTTL: schema.Int64Attribute{
				MarkdownDescription: "The TTL duration of the SecretID in seconds.",
				Optional:            true,
			},
			consts.FieldNumUses: schema.Int64Attribute{
				MarkdownDescription: "The number of uses for the secret-id.",
				Optional:            true,
			},
			consts.FieldSecretID: schema.StringAttribute{
				MarkdownDescription: "The generated SecretID.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldAccessor: schema.StringAttribute{
				MarkdownDescription: "The accessor for the SecretID.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to generate an AppRole SecretID from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *ApproleAuthBackendRoleSecretIDEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_approle_auth_backend_role_secret_id"
}

func (r *ApproleAuthBackendRoleSecretIDEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data ApproleAuthBackendRoleSecretIDEphemeralModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Set default backend if not provided
	if data.Backend.IsNull() || data.Backend.IsUnknown() {
		data.Backend = types.StringValue("approle")
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := strings.Trim(data.Backend.ValueString(), "/")
	role := strings.Trim(data.RoleName.ValueString(), "/")
	path := fmt.Sprintf("auth/%s/role/%s/secret-id", backend, role)

	// Build the request data
	requestData := make(map[string]interface{})

	// Handle CIDR list
	if !data.CIDRList.IsNull() && !data.CIDRList.IsUnknown() {
		var cidrs []string
		resp.Diagnostics.Append(data.CIDRList.ElementsAs(ctx, &cidrs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(cidrs) > 0 {
			requestData[consts.FieldCIDRList] = strings.Join(cidrs, ",")
		}
	}

	// Handle metadata
	if !data.Metadata.IsNull() && !data.Metadata.IsUnknown() {
		requestData[consts.FieldMetadata] = data.Metadata.ValueString()
	}

	// Handle TTL
	if !data.TTL.IsNull() && !data.TTL.IsUnknown() {
		requestData[consts.FieldTTL] = data.TTL.ValueInt64()
	}

	// Handle num_uses
	if !data.NumUses.IsNull() && !data.NumUses.IsUnknown() {
		requestData[consts.FieldNumUses] = data.NumUses.ValueInt64()
	}

	secretResp, err := c.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error generating AppRole SecretID",
			fmt.Sprintf("Could not generate SecretID at path %s: %s", path, err),
		)
		return
	}

	if secretResp == nil || secretResp.Data == nil {
		resp.Diagnostics.AddError(
			"Empty response from Vault",
			fmt.Sprintf("No data returned when generating SecretID at path %s", path),
		)
		return
	}

	var readResp ApproleAuthBackendRoleSecretIDAPIModel
	err = model.ToAPIModel(secretResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.SecretID = types.StringValue(readResp.SecretID)
	data.Accessor = types.StringValue(readResp.SecretIDAccessor)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)

	// Store the accessor and backend info for cleanup in Close
	resp.Private.SetKey(ctx, consts.FieldAccessor, []byte(readResp.SecretIDAccessor))
	resp.Private.SetKey(ctx, consts.FieldBackend, []byte(backend))
	resp.Private.SetKey(ctx, consts.FieldRole, []byte(role))
	resp.Private.SetKey(ctx, consts.FieldNamespace, []byte(data.Namespace.ValueString()))
}
