// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

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
	"github.com/hashicorp/vault/api"
)

const (
	fieldAccessToken  = "access_token"
	fieldExtExpiresIn = "ext_expires_in"
	fieldExpiresIn    = "expires_in"
	fieldTokenType    = "token_type"
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface.
var _ ephemeral.EphemeralResource = &AzureAccessTokenEphemeralResource{}

// NewAzureAccessTokenEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider.
var NewAzureAccessTokenEphemeralResource = func() ephemeral.EphemeralResource {
	return &AzureAccessTokenEphemeralResource{}
}

// COLE: This needed for request fields beforehand?
// AzureAccessTokenEphemeralResource implements the methods that define this resource.
type AzureAccessTokenEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// AzureAccessTokenModel describes the Terraform resource data model to match the
// resource schema.
type AzureAccessTokenModel struct {
	base.BaseModelEphemeral

	Mount types.String `tfsdk:"mount"`
	Scope types.String `tfsdk:"scope"`
	Role  types.String `tfsdk:"role"`

	AccessToken  types.String `tfsdk:"access_token"`
	TokenType    types.String `tfsdk:"token_type"`
	ExpiresIn    types.Int64  `tfsdk:"expires_in"`
	ExtExpiresIn types.Int64  `tfsdk:"ext_expires_in"`
}

// AzureAccessTokenAPIModel describes the Azure token endpoint response.
type AzureAccessTokenAPIModel struct {
	AccessToken  string `json:"access_token" mapstructure:"access_token"`
	TokenType    string `json:"token_type" mapstructure:"token_type"`
	ExpiresIn    int64  `json:"expires_in" mapstructure:"expires_in"`
	ExtExpiresIn int64  `json:"ext_expires_in" mapstructure:"ext_expires_in"`
}

// Schema defines this resource's schema.
func (r *AzureAccessTokenEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Azure Secret mount to fetch an access token for.",
				Required:            true,
			},
			consts.FieldRole: schema.StringAttribute{
				MarkdownDescription: "Static role name to fetch an access token for.",
				Required:            true,
			},
			consts.FieldScope: schema.StringAttribute{
				MarkdownDescription: "The Azure scope to request a token for.",
				Required:            true,
			},
			fieldAccessToken: schema.StringAttribute{
				MarkdownDescription: "The Azure access token.",
				Computed:            true,
				Sensitive:           true,
			},
			fieldTokenType: schema.StringAttribute{
				MarkdownDescription: "The token type returned by Azure.",
				Computed:            true,
			},
			fieldExpiresIn: schema.Int64Attribute{
				MarkdownDescription: "The access token lifetime in seconds.",
				Computed:            true,
			},
			fieldExtExpiresIn: schema.Int64Attribute{
				MarkdownDescription: "The extended access token lifetime in seconds.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to generate Azure access tokens from Vault static role credentials.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource.
func (r *AzureAccessTokenEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_access_token"
}

// Open retrieves an Azure access token for the specified static role.
func (r *AzureAccessTokenEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data AzureAccessTokenModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate that required fields are provided
	if data.Mount.IsNull() || data.Mount.ValueString() == "" {
		resp.Diagnostics.AddError("Missing required field", "The 'mount' field is required.")
		return
	}
	if data.Scope.IsNull() || data.Scope.ValueString() == "" {
		resp.Diagnostics.AddError("Missing required field", "The 'scope' field is required.")
		return
	}
	if data.Role.IsNull() || data.Role.ValueString() == "" {
		resp.Diagnostics.AddError("Missing required field", "The 'role' field is required.")
		return
	}

	// Get the Vault client from the provider configuration
	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Request the Azure access token from Vault
	tokenResp, err := requestAzureAccessToken(ctx, cli, data.Mount.ValueString(), data.Role.ValueString(), data.Scope.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to get Azure access token", err.Error())
		return
	}

	// Set the response data
	data.AccessToken = types.StringValue(tokenResp.AccessToken)
	data.TokenType = types.StringValue(tokenResp.TokenType)
	data.ExpiresIn = types.Int64Value(tokenResp.ExpiresIn)
	data.ExtExpiresIn = types.Int64Value(tokenResp.ExtExpiresIn)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func requestAzureAccessToken(ctx context.Context, cli *api.Client, mount, role, scope string) (*AzureAccessTokenAPIModel, error) {

	path := fmt.Sprintf("%s/token/%s", strings.Trim(mount, "/"), strings.Trim(role, "/")) //COLE: Trim?
	accessToken, err := cli.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"scope": scope,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to write to Vault: %w", err)
	}

	if accessToken == nil {
		return nil, fmt.Errorf("failed to obtain access token from Vault")
	}

	return &AzureAccessTokenAPIModel{
		AccessToken:  accessToken.Auth.ClientToken,
		TokenType:    "Bearer", //COLE: This is hardcoded for now, but we should get it from the response if possible
		ExpiresIn:    3600,
		ExtExpiresIn: 3600,
	}, nil
}
