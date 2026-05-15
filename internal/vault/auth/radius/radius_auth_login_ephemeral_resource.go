// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package radius

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &RadiusAuthLoginEphemeralResource{}

// NewRadiusAuthLoginEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewRadiusAuthLoginEphemeralResource = func() ephemeral.EphemeralResource {
	return &RadiusAuthLoginEphemeralResource{}
}

// RadiusAuthLoginEphemeralResource implements the methods that define this resource
type RadiusAuthLoginEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

const radiusPrivateDataKey = "radius_data"

type radiusAuthLoginPrivateData struct {
	Accessor  string `json:"accessor"`
	Namespace string `json:"namespace"`
}

// RadiusAuthLoginEphemeralModel describes the Terraform resource data model to match the
// resource schema.
type RadiusAuthLoginEphemeralModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Mount    types.String `tfsdk:"mount"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`

	// Computed fields from login response
	LeaseID          types.String `tfsdk:"lease_id"`
	LeaseDuration    types.Int64  `tfsdk:"lease_duration"`
	Renewable        types.Bool   `tfsdk:"renewable"`
	ClientToken      types.String `tfsdk:"client_token"`
	Accessor         types.String `tfsdk:"accessor"`
	TokenPolicies    types.List   `tfsdk:"token_policies"`
	IdentityPolicies types.List   `tfsdk:"identity_policies"`
	Policies         types.List   `tfsdk:"policies"`
	Metadata         types.Map    `tfsdk:"metadata"`
	EntityID         types.String `tfsdk:"entity_id"`
	Orphan           types.Bool   `tfsdk:"orphan"`
	MFARequirement   types.String `tfsdk:"mfa_requirement"`
	Data             types.Map    `tfsdk:"data"`
	Warnings         types.List   `tfsdk:"warnings"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
func (r *RadiusAuthLoginEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Unique name of the auth backend to login to.",
				Required:            true,
			},
			consts.FieldUsername: schema.StringAttribute{
				MarkdownDescription: "RADIUS username to authenticate.",
				Required:            true,
			},
			consts.FieldPassword: schema.StringAttribute{
				MarkdownDescription: "RADIUS password for the user.",
				Required:            true,
				Sensitive:           true,
			},
			consts.FieldLeaseID: schema.StringAttribute{
				MarkdownDescription: "The lease ID for the token.",
				Computed:            true,
			},
			consts.FieldLeaseDuration: schema.Int64Attribute{
				MarkdownDescription: "The lease duration in seconds.",
				Computed:            true,
			},
			consts.FieldRenewable: schema.BoolAttribute{
				MarkdownDescription: "Whether the token is renewable.",
				Computed:            true,
			},
			consts.FieldClientToken: schema.StringAttribute{
				MarkdownDescription: "The Vault token generated from successful login.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldAccessor: schema.StringAttribute{
				MarkdownDescription: "The accessor for the token.",
				Computed:            true,
			},
			consts.FieldTokenPolicies: schema.ListAttribute{
				MarkdownDescription: "List of token policies attached to the token.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			consts.FieldIdentityPolicies: schema.ListAttribute{
				MarkdownDescription: "List of identity policies attached to the token.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			consts.FieldPolicies: schema.ListAttribute{
				MarkdownDescription: "List of all policies (token + identity) attached to the token.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			consts.FieldMetadata: schema.MapAttribute{
				MarkdownDescription: "Metadata associated with the authentication.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			consts.FieldEntityID: schema.StringAttribute{
				MarkdownDescription: "The entity ID of the authenticated user.",
				Computed:            true,
			},
			consts.FieldOrphan: schema.BoolAttribute{
				MarkdownDescription: "Whether the token is an orphan.",
				Computed:            true,
			},
			consts.FieldMFARequirement: schema.StringAttribute{
				MarkdownDescription: "MFA requirement information.",
				Computed:            true,
			},
			consts.FieldData: schema.MapAttribute{
				MarkdownDescription: "Additional data from the response.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			consts.FieldWarnings: schema.ListAttribute{
				MarkdownDescription: "List of warnings returned from Vault.",
				ElementType:         types.StringType,
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to login with RADIUS authentication and obtain a Vault token.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *RadiusAuthLoginEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_radius_auth_login"
}

// Open performs the RADIUS login request and exposes the resulting Vault token
// data for the lifetime of the ephemeral resource.
func (r *RadiusAuthLoginEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data RadiusAuthLoginEphemeralModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Set default mount if not provided
	if data.Mount.IsNull() || data.Mount.IsUnknown() {
		data.Mount = types.StringValue("radius")
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := strings.Trim(data.Mount.ValueString(), "/")
	username := strings.Trim(data.Username.ValueString(), "/")
	path := fmt.Sprintf("auth/%s/login/%s", mount, username)

	// Build the request data
	requestData := map[string]interface{}{
		"password": data.Password.ValueString(),
	}

	// Perform the login
	loginResp, err := c.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error logging in with RADIUS",
			fmt.Sprintf("Could not login at path %s: %s", path, err),
		)
		return
	}

	if loginResp == nil || loginResp.Auth == nil {
		resp.Diagnostics.AddError(
			"Empty response from Vault",
			fmt.Sprintf("No authentication data returned when logging in at path %s", path),
		)
		return
	}

	// Map the response to the data model
	if loginResp.LeaseID != "" {
		data.LeaseID = types.StringValue(loginResp.LeaseID)
	} else {
		data.LeaseID = types.StringNull()
	}
	data.LeaseDuration = types.Int64Value(int64(loginResp.Auth.LeaseDuration))
	data.Renewable = types.BoolValue(loginResp.Auth.Renewable)
	data.ClientToken = types.StringValue(loginResp.Auth.ClientToken)
	data.Accessor = types.StringValue(loginResp.Auth.Accessor)

	var listDiags diag.Diagnostics
	data.TokenPolicies, listDiags = listValueFromStringsOrNull(ctx, loginResp.Auth.TokenPolicies)
	resp.Diagnostics.Append(listDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.IdentityPolicies, listDiags = listValueFromStringsOrNull(ctx, loginResp.Auth.IdentityPolicies)
	resp.Diagnostics.Append(listDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Policies, listDiags = listValueFromStringsOrNull(ctx, loginResp.Auth.Policies)
	resp.Diagnostics.Append(listDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert metadata to Map
	metadata := make(map[string]string)
	for key, value := range loginResp.Auth.Metadata {
		metadata[key] = value
	}
	var mapDiags diag.Diagnostics
	data.Metadata, mapDiags = mapValueFromStrings(ctx, metadata)
	resp.Diagnostics.Append(mapDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set additional auth fields
	data.EntityID = types.StringValue(loginResp.Auth.EntityID)
	data.Orphan = types.BoolValue(loginResp.Auth.Orphan)

	if loginResp.Auth.MFARequirement != nil {
		data.MFARequirement = types.StringValue(fmt.Sprintf("%v", loginResp.Auth.MFARequirement))
	} else {
		data.MFARequirement = types.StringNull()
	}

	// Convert data to Map (if present)
	if loginResp.Data != nil && len(loginResp.Data) > 0 {
		respData := make(map[string]string)
		for key, value := range loginResp.Data {
			respData[key] = fmt.Sprintf("%v", value)
		}
		var mapDiags diag.Diagnostics
		data.Data, mapDiags = mapValueFromStrings(ctx, respData)
		resp.Diagnostics.Append(mapDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
	} else {
		data.Data = types.MapNull(types.StringType)
	}

	data.Warnings, listDiags = listValueFromStringsOrNull(ctx, loginResp.Warnings)
	resp.Diagnostics.Append(listDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Store revocation identifiers for Close using one JSON payload in private state.
	if loginResp.Auth.Accessor != "" {
		privateData := radiusAuthLoginPrivateData{
			Accessor:  loginResp.Auth.Accessor,
			Namespace: data.Namespace.ValueString(),
		}
		privateDataJSON, err := json.Marshal(privateData)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error encoding private data",
				err.Error(),
			)
			return
		}

		resp.Private.SetKey(ctx, radiusPrivateDataKey, privateDataJSON)
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

// listValueFromStringsOrNull converts a string slice into a Terraform list and
// returns null when Vault returns no values.
func listValueFromStringsOrNull(ctx context.Context, values []string) (types.List, diag.Diagnostics) {
	if len(values) == 0 {
		return types.ListNull(types.StringType), nil
	}

	return types.ListValueFrom(ctx, types.StringType, values)
}

// mapValueFromStrings converts a string map into a Terraform map value.
func mapValueFromStrings(ctx context.Context, values map[string]string) (types.Map, diag.Diagnostics) {
	return types.MapValueFrom(ctx, types.StringType, values)
}

// Close revokes the token accessor captured during Open when the ephemeral
// resource is torn down.
func (r *RadiusAuthLoginEphemeralResource) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	privateBytes, diags := req.Private.GetKey(ctx, radiusPrivateDataKey)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if len(privateBytes) == 0 {
		return
	}

	var privateData radiusAuthLoginPrivateData
	if err := json.Unmarshal(privateBytes, &privateData); err != nil {
		tflog.Warn(ctx, fmt.Sprintf("Failed to unmarshal private data for RADIUS login cleanup: %v", err))
		return
	}

	if privateData.Accessor == "" {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), privateData.Namespace)
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if err := c.Auth().Token().RevokeAccessor(privateData.Accessor); err != nil {
		tflog.Warn(ctx, fmt.Sprintf("Failed to revoke RADIUS login token accessor %q; if not renewed, the token will expire when its TTL elapses: %v", privateData.Accessor, err))
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully revoked RADIUS login token accessor: %s", privateData.Accessor))
}
