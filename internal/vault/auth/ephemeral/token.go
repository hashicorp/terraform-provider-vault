// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralauth

import (
	"context"
	"fmt"
	"time"

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

	// input fields
	RoleName        types.String `tfsdk:"role_name"`
	Policies        types.Set    `tfsdk:"policies"`
	NoParent        types.Bool   `tfsdk:"no_parent"`
	NoDefaultPolicy types.Bool   `tfsdk:"no_default_policy"`
	Renewable       types.Bool   `tfsdk:"renewable"`
	TTL             types.String `tfsdk:"ttl"`
	ExplicitMaxTTL  types.String `tfsdk:"explicit_max_ttl"`
	Period          types.String `tfsdk:"period"`
	DisplayName     types.String `tfsdk:"display_name"`
	NumUses         types.Int64  `tfsdk:"num_uses"`
	WrappingTTL     types.String `tfsdk:"wrapping_ttl"`
	Metadata        types.Map    `tfsdk:"metadata"`

	// computed output fields
	ClientToken      types.String `tfsdk:"client_token"`
	WrappedToken     types.String `tfsdk:"wrapped_token"`
	WrappingAccessor types.String `tfsdk:"wrapping_accessor"`
	LeaseDuration    types.Int64  `tfsdk:"lease_duration"`
	LeaseStarted     types.String `tfsdk:"lease_started"`
}

// Metadata sets the full name for this resource
func (r *TokenEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_token"
}

// Schema defines this resource's schema
func (r *TokenEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provides an ephemeral resource to create a Vault token. The token is not " +
			"stored in state and will persist until its TTL or period expires.",
		Attributes: map[string]schema.Attribute{
			consts.FieldRoleName: schema.StringAttribute{
				MarkdownDescription: "The token role name.",
				Optional:            true,
			},
			consts.FieldPolicies: schema.SetAttribute{
				MarkdownDescription: "List of policies.",
				ElementType:         types.StringType,
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
			consts.FieldPeriod: schema.StringAttribute{
				MarkdownDescription: "The period of the token.",
				Optional:            true,
			},
			consts.FieldDisplayName: schema.StringAttribute{
				MarkdownDescription: "The display name of the token.",
				Optional:            true,
			},
			consts.FieldNumUses: schema.Int64Attribute{
				MarkdownDescription: "The number of allowed uses of the token.",
				Optional:            true,
			},
			consts.FieldWrappingTTL: schema.StringAttribute{
				MarkdownDescription: "The TTL period of the wrapped token.",
				Optional:            true,
			},
			consts.FieldMetadata: schema.MapAttribute{
				MarkdownDescription: "Metadata to be associated with the token.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			consts.FieldClientToken: schema.StringAttribute{
				MarkdownDescription: "The client token.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldWrappedToken: schema.StringAttribute{
				MarkdownDescription: "The client wrapped token.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldWrappingAccessor: schema.StringAttribute{
				MarkdownDescription: "The client wrapping accessor.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldLeaseDuration: schema.Int64Attribute{
				MarkdownDescription: "The token lease duration.",
				Computed:            true,
			},
			consts.FieldLeaseStarted: schema.StringAttribute{
				MarkdownDescription: "The token lease started on.",
				Computed:            true,
			},
		},
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (r *TokenEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data TokenEphemeralModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	createRequest := &api.TokenCreateRequest{}

	if !data.Policies.IsNull() && !data.Policies.IsUnknown() {
		var policies []string
		resp.Diagnostics.Append(data.Policies.ElementsAs(ctx, &policies, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.Policies = policies
	}

	if !data.TTL.IsNull() && !data.TTL.IsUnknown() {
		createRequest.TTL = data.TTL.ValueString()
	}

	if !data.ExplicitMaxTTL.IsNull() && !data.ExplicitMaxTTL.IsUnknown() {
		createRequest.ExplicitMaxTTL = data.ExplicitMaxTTL.ValueString()
	}

	if !data.Period.IsNull() && !data.Period.IsUnknown() {
		createRequest.Period = data.Period.ValueString()
	}

	if !data.NoParent.IsNull() && !data.NoParent.IsUnknown() {
		createRequest.NoParent = data.NoParent.ValueBool()
	}

	if !data.NoDefaultPolicy.IsNull() && !data.NoDefaultPolicy.IsUnknown() {
		createRequest.NoDefaultPolicy = data.NoDefaultPolicy.ValueBool()
	}

	if !data.DisplayName.IsNull() && !data.DisplayName.IsUnknown() {
		createRequest.DisplayName = data.DisplayName.ValueString()
	}

	if !data.NumUses.IsNull() && !data.NumUses.IsUnknown() {
		createRequest.NumUses = int(data.NumUses.ValueInt64())
	}

	if !data.Renewable.IsNull() && !data.Renewable.IsUnknown() {
		renewable := data.Renewable.ValueBool()
		createRequest.Renewable = &renewable
	}

	if !data.Metadata.IsNull() && !data.Metadata.IsUnknown() {
		metadata := make(map[string]string)
		resp.Diagnostics.Append(data.Metadata.ElementsAs(ctx, &metadata, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.Metadata = metadata
	}

	var wrapped bool
	if !data.WrappingTTL.IsNull() && !data.WrappingTTL.IsUnknown() {
		wrappingTTL := data.WrappingTTL.ValueString()

		c, err = c.Clone()
		if err != nil {
			resp.Diagnostics.AddError(
				"Error cloning Vault client",
				fmt.Sprintf("Could not clone Vault client: %s", err),
			)
			return
		}

		c.SetWrappingLookupFunc(func(operation, path string) string {
			return wrappingTTL
		})

		wrapped = true
	}

	var secret *api.Secret
	role := data.RoleName.ValueString()

	if role != "" {
		secret, err = c.Auth().Token().CreateWithRole(createRequest, role)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error creating token",
				fmt.Sprintf("Could not create token with role %q: %s", role, err),
			)
			return
		}
	} else {
		secret, err = c.Auth().Token().Create(createRequest)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error creating token",
				fmt.Sprintf("Could not create token: %s", err),
			)
			return
		}
	}

	if secret == nil {
		resp.Diagnostics.AddError(
			"Empty response from Vault",
			"No data returned when creating token",
		)
		return
	}

	if wrapped {
		if secret.WrapInfo == nil {
			resp.Diagnostics.AddError(
				"Empty wrap info from Vault",
				"No wrap info returned when creating wrapped token",
			)
			return
		}
		data.WrappedToken = types.StringValue(secret.WrapInfo.Token)
		data.WrappingAccessor = types.StringValue(secret.WrapInfo.Accessor)
	} else {
		if secret.Auth == nil {
			resp.Diagnostics.AddError(
				"Empty auth response from Vault",
				"No auth data returned when creating token",
			)
			return
		}
		data.ClientToken = types.StringValue(secret.Auth.ClientToken)
		data.LeaseDuration = types.Int64Value(int64(secret.Auth.LeaseDuration))
		data.LeaseStarted = types.StringValue(time.Now().Format(time.RFC3339))
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
