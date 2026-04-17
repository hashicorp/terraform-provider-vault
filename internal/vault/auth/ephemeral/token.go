// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &TokenEphemeralResource{}

// NewTokenEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewTokenEphemeralResource = func() ephemeral.EphemeralResource {
	return &TokenEphemeralResource{}
}

// TokenEphemeralResource implements the methods that define this resource
type TokenEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// TokenEphemeralModel describes the Terraform resource data model to match the
// resource schema.
type TokenEphemeralModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// Input fields
	ID              types.String `tfsdk:"id"`
	RoleName        types.String `tfsdk:"role_name"`
	Policies        types.Set    `tfsdk:"policies"`
	NoParent        types.Bool   `tfsdk:"no_parent"`
	NoDefaultPolicy types.Bool   `tfsdk:"no_default_policy"`
	Renewable       types.Bool   `tfsdk:"renewable"`
	TTL             types.String `tfsdk:"ttl"`
	ExplicitMaxTTL  types.String `tfsdk:"explicit_max_ttl"`
	DisplayName     types.String `tfsdk:"display_name"`
	NumUses         types.Int64  `tfsdk:"num_uses"`
	Period          types.String `tfsdk:"period"`
	Metadata        types.Map    `tfsdk:"metadata"`
	Type            types.String `tfsdk:"type"`
	EntityAlias     types.String `tfsdk:"entity_alias"`
	WrappingTTL     types.String `tfsdk:"wrapping_ttl"`

	// Computed output fields
	ClientToken      types.String `tfsdk:"client_token"`
	WrappedToken     types.String `tfsdk:"wrapped_token"`
	WrappingAccessor types.String `tfsdk:"wrapping_accessor"`
	LeaseDuration    types.Int64  `tfsdk:"lease_duration"`
	LeaseID          types.String `tfsdk:"lease_id"`
	Accessor         types.String `tfsdk:"accessor"`
	TokenPolicies    types.List   `tfsdk:"token_policies"`
	EntityID         types.String `tfsdk:"entity_id"`
	Orphan           types.Bool   `tfsdk:"orphan"`
}

// TokenPrivateData stores information needed for token revocation in Close()
type TokenPrivateData struct {
	Accessor  string `json:"accessor,omitempty"`
	LeaseID   string `json:"lease_id,omitempty"`
	TokenType string `json:"token_type"`
	Wrapped   bool   `json:"wrapped"`
	Namespace string `json:"namespace,omitempty"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
func (r *TokenEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldID: schema.StringAttribute{
				MarkdownDescription: "The ID of the client token. Can only be specified by a root token. The ID provided may not contain a '.' character and should not start with the 's.' prefix.",
				Optional:            true,
			},
			consts.FieldRoleName: schema.StringAttribute{
				MarkdownDescription: "The token role name.",
				Optional:            true,
			},
			consts.FieldPolicies: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of policies to attach to the token.",
				Optional:            true,
			},
			consts.FieldNoParent: schema.BoolAttribute{
				MarkdownDescription: "Flag to create a token without parent.",
				Optional:            true,
			},
			consts.FieldNoDefaultPolicy: schema.BoolAttribute{
				MarkdownDescription: "Flag to disable the default policy.",
				Optional:            true,
			},
			consts.FieldRenewable: schema.BoolAttribute{
				MarkdownDescription: "Flag to allow the token to be renewed.",
				Optional:            true,
			},
			consts.FieldTTL: schema.StringAttribute{
				MarkdownDescription: "The TTL period of the token.",
				Optional:            true,
			},
			consts.FieldExplicitMaxTTL: schema.StringAttribute{
				MarkdownDescription: "The explicit max TTL of the token.",
				Optional:            true,
			},
			consts.FieldDisplayName: schema.StringAttribute{
				MarkdownDescription: "The display name of the token.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldNumUses: schema.Int64Attribute{
				MarkdownDescription: "The number of allowed uses of the token.",
				Optional:            true,
			},
			consts.FieldPeriod: schema.StringAttribute{
				MarkdownDescription: "The period of the token for periodic tokens.",
				Optional:            true,
			},
			consts.FieldMetadata: schema.MapAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Metadata to be associated with the token.",
				Optional:            true,
			},
			consts.FieldType: schema.StringAttribute{
				MarkdownDescription: "The token type. Can be 'batch' or 'service'.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldEntityAlias: schema.StringAttribute{
				MarkdownDescription: "Name of the entity alias to associate with during token creation.",
				Optional:            true,
			},
			consts.FieldWrappingTTL: schema.StringAttribute{
				MarkdownDescription: "The TTL period of the wrapped token.",
				Optional:            true,
			},
			consts.FieldClientToken: schema.StringAttribute{
				MarkdownDescription: "The client token value.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldWrappedToken: schema.StringAttribute{
				MarkdownDescription: "The wrapped token value.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldWrappingAccessor: schema.StringAttribute{
				MarkdownDescription: "The wrapping accessor.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldLeaseDuration: schema.Int64Attribute{
				MarkdownDescription: "The token lease duration.",
				Computed:            true,
			},
			consts.FieldLeaseID: schema.StringAttribute{
				MarkdownDescription: "The lease ID associated with the token.",
				Computed:            true,
			},
			consts.FieldAccessor: schema.StringAttribute{
				MarkdownDescription: "The token accessor.",
				Computed:            true,
			},
			consts.FieldTokenPolicies: schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "The list of policies attached to the token.",
				Computed:            true,
			},
			consts.FieldEntityID: schema.StringAttribute{
				MarkdownDescription: "The entity ID associated with the token.",
				Computed:            true,
			},
			consts.FieldOrphan: schema.BoolAttribute{
				MarkdownDescription: "Whether the token is an orphan token.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to create Vault tokens with automatic revocation.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *TokenEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_token"
}

// Open creates the token and stores necessary information for revocation
func (r *TokenEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data TokenEphemeralModel

	// Read Terraform configuration into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set default values only if null or known empty string (not if unknown)
	if data.DisplayName.IsNull() || (!data.DisplayName.IsUnknown() && data.DisplayName.ValueString() == "") {
		data.DisplayName = types.StringValue("token")
	}
	if data.Type.IsNull() || (!data.Type.IsUnknown() && data.Type.ValueString() == "") {
		data.Type = types.StringValue("service")
	}

	// Get Vault client
	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Build token create request
	createRequest := &api.TokenCreateRequest{}

	// Set policies
	if !data.Policies.IsNull() && !data.Policies.IsUnknown() {
		var policies []string
		resp.Diagnostics.Append(data.Policies.ElementsAs(ctx, &policies, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.Policies = policies
	}

	// Set ID field (root only)
	if !data.ID.IsNull() && !data.ID.IsUnknown() {
		createRequest.ID = data.ID.ValueString()
	}

	// Set string fields
	if !data.TTL.IsNull() && !data.TTL.IsUnknown() {
		createRequest.TTL = data.TTL.ValueString()
	}
	if !data.ExplicitMaxTTL.IsNull() && !data.ExplicitMaxTTL.IsUnknown() {
		createRequest.ExplicitMaxTTL = data.ExplicitMaxTTL.ValueString()
	}
	if !data.Period.IsNull() && !data.Period.IsUnknown() {
		createRequest.Period = data.Period.ValueString()
	}
	if !data.DisplayName.IsNull() && !data.DisplayName.IsUnknown() {
		createRequest.DisplayName = data.DisplayName.ValueString()
	}
	if !data.Type.IsNull() && !data.Type.IsUnknown() {
		createRequest.Type = data.Type.ValueString()
	}
	if !data.EntityAlias.IsNull() && !data.EntityAlias.IsUnknown() {
		createRequest.EntityAlias = data.EntityAlias.ValueString()
	}

	// Set boolean fields
	if !data.NoParent.IsNull() && !data.NoParent.IsUnknown() {
		createRequest.NoParent = data.NoParent.ValueBool()
	}
	if !data.NoDefaultPolicy.IsNull() && !data.NoDefaultPolicy.IsUnknown() {
		createRequest.NoDefaultPolicy = data.NoDefaultPolicy.ValueBool()
	}
	if !data.Renewable.IsNull() && !data.Renewable.IsUnknown() {
		renewable := data.Renewable.ValueBool()
		createRequest.Renewable = &renewable
	}

	// Set numeric fields
	if !data.NumUses.IsNull() && !data.NumUses.IsUnknown() {
		createRequest.NumUses = int(data.NumUses.ValueInt64())
	}

	// Set metadata
	if !data.Metadata.IsNull() && !data.Metadata.IsUnknown() {
		metadata := make(map[string]string)
		resp.Diagnostics.Append(data.Metadata.ElementsAs(ctx, &metadata, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.Metadata = metadata
	}

	// Handle wrapping if wrapping_ttl is set
	var wrapped bool
	if !data.WrappingTTL.IsNull() && !data.WrappingTTL.IsUnknown() && data.WrappingTTL.ValueString() != "" {
		wrappingTTL := data.WrappingTTL.ValueString()

		// Clone client for wrapping
		c, err = c.Clone()
		if err != nil {
			resp.Diagnostics.AddError(
				"Error cloning client for wrapping",
				fmt.Sprintf("Could not clone Vault client: %s", err),
			)
			return
		}

		c.SetWrappingLookupFunc(func(operation, path string) string {
			return wrappingTTL
		})

		wrapped = true
	}

	// Create the token
	var tokenResp *api.Secret
	var roleName string
	if !data.RoleName.IsNull() && !data.RoleName.IsUnknown() {
		roleName = data.RoleName.ValueString()
	}

	if roleName != "" {
		tokenResp, err = c.Auth().Token().CreateWithRole(createRequest, roleName)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error creating token with role",
				fmt.Sprintf("Could not create token with role %q: %s", roleName, err),
			)
			return
		}
	} else {
		tokenResp, err = c.Auth().Token().Create(createRequest)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error creating token",
				fmt.Sprintf("Could not create token: %s", err),
			)
			return
		}
	}

	if tokenResp == nil {
		resp.Diagnostics.AddError(
			"Empty response from Vault",
			"Vault returned an empty response when creating token",
		)
		return
	}

	// Extract token information based on whether it's wrapped
	var accessor string
	var leaseID string
	var tokenType string

	if wrapped {
		// Wrapped token
		if tokenResp.WrapInfo == nil {
			resp.Diagnostics.AddError(
				"Invalid wrapped token response",
				"Vault returned a wrapped token response without WrapInfo",
			)
			return
		}
		data.WrappedToken = types.StringValue(tokenResp.WrapInfo.Token)
		data.WrappingAccessor = types.StringValue(tokenResp.WrapInfo.Accessor)
		accessor = tokenResp.WrapInfo.WrappedAccessor
		data.LeaseDuration = types.Int64Value(int64(tokenResp.WrapInfo.TTL))

		// Wrapped batch tokens do not include a wrapped accessor. Detect that
		// case so later cleanup does not treat them like revocable service tokens.
		if accessor == "" {
			tokenType = "batch"
			data.Type = types.StringValue("batch")
		} else {
			tokenType = data.Type.ValueString()
		}
	} else {
		// Regular token
		if tokenResp.Auth == nil {
			resp.Diagnostics.AddError(
				"Invalid token response",
				"Vault returned a token response without Auth information",
			)
			return
		}
		data.ClientToken = types.StringValue(tokenResp.Auth.ClientToken)
		accessor = tokenResp.Auth.Accessor
		leaseID = tokenResp.LeaseID
		data.LeaseDuration = types.Int64Value(int64(tokenResp.Auth.LeaseDuration))

		// Handle batch tokens (no accessor)
		if accessor == "" && tokenResp.Auth.ClientToken != "" && strings.HasPrefix(tokenResp.Auth.ClientToken, "hvb.") {
			accessor = tokenResp.RequestID
			tokenType = "batch"
			data.Type = types.StringValue("batch")
		} else {
			tokenType = data.Type.ValueString()
		}
	}

	// Set computed fields
	if accessor != "" {
		data.Accessor = types.StringValue(accessor)
	}
	if leaseID != "" {
		data.LeaseID = types.StringValue(leaseID)
	}

	// Set additional computed fields from auth response
	if !wrapped && tokenResp.Auth != nil {
		// Token policies
		if len(tokenResp.Auth.TokenPolicies) > 0 {
			policies := make([]types.String, len(tokenResp.Auth.TokenPolicies))
			for i, p := range tokenResp.Auth.TokenPolicies {
				policies[i] = types.StringValue(p)
			}
			policyList, diags := types.ListValueFrom(ctx, types.StringType, policies)
			resp.Diagnostics.Append(diags...)
			if !resp.Diagnostics.HasError() {
				data.TokenPolicies = policyList
			}
		}

		// Entity ID
		if tokenResp.Auth.EntityID != "" {
			data.EntityID = types.StringValue(tokenResp.Auth.EntityID)
		}

		// Orphan status
		data.Orphan = types.BoolValue(tokenResp.Auth.Orphan)
	}

	// Store private data for Close()
	privateData := TokenPrivateData{
		Accessor:  accessor,
		LeaseID:   leaseID,
		TokenType: tokenType,
		Wrapped:   wrapped,
		Namespace: data.Namespace.ValueString(),
	}

	privateBytes, err := json.Marshal(privateData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error marshaling private data",
			fmt.Sprintf("Could not marshal private data: %s", err),
		)
		return
	}

	resp.Private.SetKey(ctx, "private_data", privateBytes)

	// Set the result
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

// Close revokes the token when it's no longer needed
func (r *TokenEphemeralResource) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	// Retrieve private data
	privateBytes, diags := req.Private.GetKey(ctx, "private_data")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var privateData TokenPrivateData
	if err := json.Unmarshal(privateBytes, &privateData); err != nil {
		resp.Diagnostics.AddError(
			"Error unmarshaling private data",
			fmt.Sprintf("Could not unmarshal private data: %s", err),
		)
		return
	}

	// Batch tokens cannot be revoked via API
	if privateData.TokenType == "batch" {
		// Batch tokens expire naturally, no revocation needed
		return
	}

	// Get Vault client
	c, err := client.GetClient(ctx, r.Meta(), privateData.Namespace)
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Revoke the token
	if privateData.Accessor != "" {
		err = c.Auth().Token().RevokeAccessor(privateData.Accessor)
		if err != nil {
			// Log warning but don't fail - token will expire anyway
			resp.Diagnostics.AddWarning(
				"Error revoking token",
				fmt.Sprintf("Could not revoke token with accessor %q: %s. Token will expire based on its TTL.", privateData.Accessor, err),
			)
			return
		}
	} else if privateData.LeaseID != "" {
		// Try revoking by lease ID as fallback
		err = c.Sys().RevokeWithContext(ctx, privateData.LeaseID)
		if err != nil {
			resp.Diagnostics.AddWarning(
				"Error revoking token",
				fmt.Sprintf("Could not revoke token with lease ID %q: %s. Token will expire based on its TTL.", privateData.LeaseID, err),
			)
			return
		}
	} else {
		resp.Diagnostics.AddWarning(
			"No accessor or lease ID available",
			"Token will not be revoked as no accessor or lease ID was provided. Token will expire based on its TTL.",
		)
	}
}
