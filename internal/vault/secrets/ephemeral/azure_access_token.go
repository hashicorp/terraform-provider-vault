// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/vault/api"
)

var azureAccessTokenBaseURL = "https://login.microsoftonline.com"

const (
	fieldAccessToken  = "access_token"
	fieldExtExpiresIn = "ext_expires_in"
	fieldExpiresIn    = "expires_in"
	fieldTokenType    = "token_type"
	fieldGrantType    = "grant_type"
	fieldClientSecret = "client_secret"
	fieldClientID     = "client_id"
)

var azureTokenRequestDoer = func(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface.
var _ ephemeral.EphemeralResource = &AzureAccessTokenEphemeralResource{}

// NewAzureAccessTokenEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider.
var NewAzureAccessTokenEphemeralResource = func() ephemeral.EphemeralResource {
	return &AzureAccessTokenEphemeralResource{}
}

// AzureAccessTokenEphemeralResource implements the methods that define this resource.
type AzureAccessTokenEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// AzureAccessTokenModel describes the Terraform resource data model to match the
// resource schema.
type AzureAccessTokenModel struct {
	base.BaseModelEphemeral

	Backend types.String `tfsdk:"backend"`
	Role    types.String `tfsdk:"role"`
	Scope   types.String `tfsdk:"scope"`

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

// AzureAccessTokenBackendConfigModel describes the Azure backend config response.
type AzureAccessTokenBackendConfigModel struct {
	TenantID string `json:"tenant_id" mapstructure:"tenant_id"`
}

// AzureAccessTokenStaticCredsModel describes the Azure static creds response.
type AzureAccessTokenStaticCredsModel struct {
	ClientID     string `json:"client_id" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret" mapstructure:"client_secret"`
}

// Schema defines this resource's schema.
func (r *AzureAccessTokenEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "Azure Secret Backend to read credentials from.",
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

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	tenantID, err := readAzureBackendTenantID(ctx, cli, data.Backend.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Azure backend configuration", err.Error())
		return
	}

	staticCreds, err := readAzureStaticRoleCredentials(ctx, cli, data.Backend.ValueString(), data.Role.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Azure static role credentials", err.Error())
		return
	}

	tokenResp, err := requestAzureAccessToken(ctx, tenantID, staticCreds.ClientID, staticCreds.ClientSecret, data.Scope.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to get Azure access token", err.Error())
		return
	}

	data.AccessToken = types.StringValue(tokenResp.AccessToken)
	data.TokenType = types.StringValue(tokenResp.TokenType)
	data.ExpiresIn = types.Int64Value(tokenResp.ExpiresIn)
	data.ExtExpiresIn = types.Int64Value(tokenResp.ExtExpiresIn)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func readAzureBackendTenantID(ctx context.Context, cli *api.Client, backend string) (string, error) {
	resp, err := cli.Logical().ReadWithContext(ctx, strings.Trim(backend, "/")+"/config")
	if err != nil {
		title, detail := errutil.VaultReadErr(err)
		return "", fmt.Errorf("%s: %s", title, detail)
	}
	if resp == nil {
		title, detail := errutil.VaultReadResponseNil()
		return "", fmt.Errorf("%s: %s", title, detail)
	}

	var apiResp AzureAccessTokenBackendConfigModel
	if err := model.ToAPIModel(resp.Data, &apiResp); err != nil {
		return "", fmt.Errorf("unable to translate Vault response data: %w", err)
	}
	if apiResp.TenantID == "" {
		return "", fmt.Errorf("azure backend config did not return tenant_id")
	}

	return apiResp.TenantID, nil
}

func readAzureStaticRoleCredentials(ctx context.Context, cli *api.Client, backend, role string) (*AzureAccessTokenStaticCredsModel, error) {
	path := fmt.Sprintf("%s/static-creds/%s", strings.Trim(backend, "/"), strings.Trim(role, "/"))
	resp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		title, detail := errutil.VaultReadErr(err)
		return nil, fmt.Errorf("%s: %s", title, detail)
	}
	if resp == nil {
		title, detail := errutil.VaultReadResponseNil()
		return nil, fmt.Errorf("%s: %s", title, detail)
	}

	var apiResp AzureAccessTokenStaticCredsModel
	if err := model.ToAPIModel(resp.Data, &apiResp); err != nil {
		return nil, fmt.Errorf("unable to translate Vault response data: %w", err)
	}
	if apiResp.ClientID == "" || apiResp.ClientSecret == "" {
		return nil, fmt.Errorf("azure static role did not return client_id and client_secret")
	}

	return &apiResp, nil
}

func requestAzureAccessToken(ctx context.Context, tenantID, clientID, clientSecret, scope string) (*AzureAccessTokenAPIModel, error) {
	formData := url.Values{}
	formData.Set(fieldGrantType, "client_credentials")
	formData.Set(fieldClientID, clientID)
	formData.Set(fieldClientSecret, clientSecret)
	formData.Set(consts.FieldScope, scope)

	tokenURL := strings.TrimRight(azureAccessTokenBaseURL, "/") + "/" + url.PathEscape(tenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := azureTokenRequestDoer(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("azure token request failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var apiResp AzureAccessTokenAPIModel
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	if apiResp.AccessToken == "" {
		return nil, fmt.Errorf("azure token response did not contain access_token")
	}

	return &apiResp, nil
}
