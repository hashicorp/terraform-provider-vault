// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &GCPOAuth2AccessTokenEphemeralResource{}

// NewGCPOAuth2AccessTokenEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewGCPOAuth2AccessTokenEphemeralResource = func() ephemeral.EphemeralResource {
	return &GCPOAuth2AccessTokenEphemeralResource{}
}

// GCPOAuth2AccessTokenEphemeralResource implements the methods that define this resource
type GCPOAuth2AccessTokenEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// GCPOAuth2AccessTokenModel describes the Terraform resource data model to match the
// resource schema.
type GCPOAuth2AccessTokenModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Backend       types.String `tfsdk:"backend"`
	Roleset       types.String `tfsdk:"roleset"`
	StaticAccount types.String `tfsdk:"static_account"`

	// computed fields
	Token               types.String `tfsdk:"token"`
	TokenTTL            types.Int64  `tfsdk:"token_ttl"`
	ServiceAccountEmail types.String `tfsdk:"service_account_email"`
	LeaseID             types.String `tfsdk:"lease_id"`
	LeaseDuration       types.Int64  `tfsdk:"lease_duration"`
	LeaseStartTime      types.String `tfsdk:"lease_start_time"`
	LeaseRenewable      types.Bool   `tfsdk:"lease_renewable"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
func (r *GCPOAuth2AccessTokenEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"backend": schema.StringAttribute{
				MarkdownDescription: "GCP Secret Backend to read credentials from.",
				Required:            true,
			},
			"roleset": schema.StringAttribute{
				MarkdownDescription: "GCP Secret Roleset to generate OAuth2 access token for. Mutually exclusive with `static_account`.",
				Optional:            true,
			},
			"static_account": schema.StringAttribute{
				MarkdownDescription: "GCP Secret Static Account to generate OAuth2 access token for. Mutually exclusive with `roleset`.",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "The OAuth2 access token.",
				Computed:            true,
				Sensitive:           true,
			},
			"token_ttl": schema.Int64Attribute{
				MarkdownDescription: "The TTL of the token in seconds.",
				Computed:            true,
			},
			"service_account_email": schema.StringAttribute{
				MarkdownDescription: "The email of the service account.",
				Computed:            true,
			},
			consts.FieldLeaseID: schema.StringAttribute{
				MarkdownDescription: "Lease identifier assigned by vault.",
				Computed:            true,
			},
			consts.FieldLeaseDuration: schema.Int64Attribute{
				MarkdownDescription: "Lease duration in seconds relative to the time in lease_start_time.",
				Computed:            true,
			},
			"lease_start_time": schema.StringAttribute{
				MarkdownDescription: "Time at which the lease was read, using the clock of the system where Terraform was running.",
				Computed:            true,
			},
			consts.FieldLeaseRenewable: schema.BoolAttribute{
				MarkdownDescription: "True if the duration of this lease can be extended through renewal.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to generate GCP OAuth2 access tokens from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *GCPOAuth2AccessTokenEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcp_oauth2_access_token"
}

func (r *GCPOAuth2AccessTokenEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GCPOAuth2AccessTokenModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Validate that either roleset or static_account is provided, but not both
	hasRoleset := !data.Roleset.IsNull() && data.Roleset.ValueString() != ""
	hasStaticAccount := !data.StaticAccount.IsNull() && data.StaticAccount.ValueString() != ""

	if !hasRoleset && !hasStaticAccount {
		resp.Diagnostics.AddError(
			"Missing required field",
			"Either 'roleset' or 'static_account' must be provided",
		)
		return
	}

	if hasRoleset && hasStaticAccount {
		resp.Diagnostics.AddError(
			"Conflicting fields",
			"Only one of 'roleset' or 'static_account' can be provided, not both",
		)
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	var tokenPath string

	if hasRoleset {
		roleset := data.Roleset.ValueString()
		tokenPath = backend + "/token/" + roleset
	} else {
		staticAccount := data.StaticAccount.ValueString()
		tokenPath = backend + "/static-account/" + staticAccount + "/token"
	}

	// Read the OAuth2 access token from Vault (GET request)
	vaultSecret, readErr := c.Logical().ReadWithContext(ctx, tokenPath)
	if readErr != nil {
		resp.Diagnostics.AddError(
			"Error reading from Vault",
			fmt.Sprintf("Error generating GCP OAuth2 access token from path %q: %s", tokenPath, readErr),
		)
		return
	}

	if vaultSecret == nil {
		resp.Diagnostics.AddError(
			"No credentials found",
			fmt.Sprintf("No credentials found at path %q", tokenPath),
		)
		return
	}

	log.Printf("[DEBUG] Generated GCP OAuth2 access token from %q", tokenPath)

	// Extract token
	token, ok := vaultSecret.Data["token"].(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Invalid response from Vault",
			"token field not found or not a string in Vault response",
		)
		return
	}
	data.Token = types.StringValue(token)

	// Extract token_ttl if present
	if tokenTTL, ok := vaultSecret.Data["token_ttl"].(float64); ok {
		data.TokenTTL = types.Int64Value(int64(tokenTTL))
	} else if tokenTTL, ok := vaultSecret.Data["token_ttl"].(int64); ok {
		data.TokenTTL = types.Int64Value(tokenTTL)
	}

	// Extract service_account_email if present
	if email, ok := vaultSecret.Data["service_account_email"].(string); ok {
		data.ServiceAccountEmail = types.StringValue(email)
	}

	// Set lease information
	data.LeaseID = types.StringValue(vaultSecret.LeaseID)
	data.LeaseDuration = types.Int64Value(int64(vaultSecret.LeaseDuration))
	data.LeaseStartTime = types.StringValue(time.Now().Format(time.RFC3339))
	data.LeaseRenewable = types.BoolValue(vaultSecret.Renewable)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

// Made with Bob
