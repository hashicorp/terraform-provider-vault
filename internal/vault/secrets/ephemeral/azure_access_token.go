// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/api"
)

const (
	fieldAccessToken  = "access_token"
	fieldExtExpiresIn = "ext_expires_in"
	fieldExpiresIn    = "expires_in"

	// azureADClientSecretNotPropagated is the Azure AD error code returned when a
	// client secret exists in Vault but has not yet replicated across Azure AD.
	azureADClientSecretNotPropagated = "AADSTS7000215"
)

// isAzureCredPropagationError checks if the error indicates an Azure AD credential
// that exists in Vault but has not yet propagated. This is a retryable condition.
func isAzureCredPropagationError(err error) bool {
	var respErr *api.ResponseError
	if errors.As(err, &respErr) {
		if respErr.StatusCode == http.StatusBadRequest {
			return len(respErr.Errors) == 1 &&
				strings.Contains(respErr.Errors[0], azureADClientSecretNotPropagated)
		}
	}
	return false
}

// isAzureCredNotInitializedError checks if the error indicates the static credential
// has not yet been provisioned and needs to be initialized via static-creds/.
func isAzureCredNotInitializedError(err error) bool {
	var respErr *api.ResponseError
	if errors.As(err, &respErr) {
		if respErr.StatusCode == http.StatusBadRequest {
			return len(respErr.Errors) == 1 &&
				strings.Contains(respErr.Errors[0], "rotate the role once before token generation")
		}
	}
	return false
}

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface.
var _ ephemeral.EphemeralResource = &AzureAccessTokenEphemeralResource{}

// NewAzureAccessTokenEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider.
func NewAzureAccessTokenEphemeralResource() ephemeral.EphemeralResource {
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

	// Inputs
	Mount      types.String `tfsdk:"mount"`
	Scope      types.String `tfsdk:"scope"`
	Role       types.String `tfsdk:"role"`
	MaxRetries types.Int64  `tfsdk:"max_retries"`
	RetryDelay types.Int64  `tfsdk:"retry_delay"`

	// Outputs
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
				MarkdownDescription: "Mount path for the Azure secret engine in Vault.",
				Required:            true,
			},
			consts.FieldRole: schema.StringAttribute{
				MarkdownDescription: "Static role name to fetch an access token for.",
				Required:            true,
			},
			consts.FieldScope: schema.StringAttribute{
				MarkdownDescription: "The Azure OAuth2 scope to request the access token for (e.g. \"https://graph.microsoft.com/.default\").",
				Required:            true,
			},
			consts.FieldMaxRetries: schema.Int64Attribute{
				MarkdownDescription: fmt.Sprintf("Maximum number of retries when waiting for the Azure AD credential to propagate. Defaults to %d.", credPropagationRetries),
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},
			consts.FieldRetryDelay: schema.Int64Attribute{
				MarkdownDescription: fmt.Sprintf("Number of seconds to wait between propagation retries. Defaults to %d.", int(credPropagationDelay.Seconds())),
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},
			fieldAccessToken: schema.StringAttribute{
				MarkdownDescription: "The Azure access token.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldTokenType: schema.StringAttribute{
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
		MarkdownDescription: "Provides an ephemeral resource to fetch Azure access tokens from Vault static role credentials.",
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

	if !r.Meta().IsAPISupported(provider.VaultVersion220) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			"vault_azure_access_token requires Vault version 2.2.0 or later.",
		)
		return
	}

	// Get the Vault client from the provider configuration
	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Apply user-supplied overrides for propagation retry behaviour, falling
	// back to the package-level defaults if not set.
	maxRetries := credPropagationRetries
	if !data.MaxRetries.IsNull() && !data.MaxRetries.IsUnknown() {
		maxRetries = int(data.MaxRetries.ValueInt64())
	}
	retryDelay := credPropagationDelay
	if !data.RetryDelay.IsNull() && !data.RetryDelay.IsUnknown() {
		retryDelay = time.Duration(data.RetryDelay.ValueInt64()) * time.Second
	}

	// Request the Azure access token from Vault
	tokenResp, err := requestAzureAccessToken(ctx, cli, data.Mount.ValueString(), data.Role.ValueString(), data.Scope.ValueString(), maxRetries, retryDelay)
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

// credPropagationRetries is the number of times to retry.
const credPropagationRetries = 4

// credPropagationDelay is the wait between retries.
const credPropagationDelay = 4 * time.Second

// requestAzureAccessToken fetches an Azure OAuth2 access token from Vault's static-creds/<role>/token endpoint,
// initializing the static credential on first use and retrying on Azure AD propagation errors.
func requestAzureAccessToken(ctx context.Context, cli *api.Client, mount, role, scope string, maxRetries int, retryDelay time.Duration) (*AzureAccessTokenAPIModel, error) {
	path := fmt.Sprintf("%s/static-creds/%s/token", mount, role)
	initialized := false

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay):
			}
		}

		secret, err := cli.Logical().WriteWithContext(ctx, path, map[string]interface{}{
			"scope": scope,
		})
		if err != nil {
			// AADSTS7000215 means the client secret exists in Vault but has not
			// yet propagated across Azure AD. Retry after a short wait.
			if isAzureCredPropagationError(err) {
				tflog.Warn(ctx, fmt.Sprintf(
					"Azure AD has not yet accepted the client secret (AADSTS7000215); "+
						"retrying in %s (attempt %d/%d)",
					retryDelay, attempt+1, maxRetries,
				))
				continue
			}
			// static-creds/<role>/token returns a 400 when the static credential has not yet been
			// provisioned. Reading static-creds/ initializes it on first access.
			// This only happens once — on every subsequent Open() the credential
			// already exists and static-creds/<role>/token succeeds on the first attempt.
			if !initialized && isAzureCredNotInitializedError(err) {
				tflog.Info(ctx, fmt.Sprintf(
					"Static credential for role %q not yet provisioned; initializing via static-creds/",
					role,
				))
				staticCredsPath := fmt.Sprintf("%s/static-creds/%s", mount, role)
				sec, initErr := cli.Logical().ReadWithContext(ctx, staticCredsPath)
				if initErr != nil {
					return nil, fmt.Errorf("unable to initialize static credential: %w", initErr)
				}
				if sec == nil {
					return nil, fmt.Errorf("unable to initialize static credential: role %q not found", role)
				}
				initialized = true
				continue
			}
			return nil, fmt.Errorf("unable to get Azure access token from Vault: %w", err)
		}

		if secret == nil {
			return nil, fmt.Errorf("no response returned from Vault")
		}

		var tokenResp AzureAccessTokenAPIModel
		if err := model.ToAPIModel(secret.Data, &tokenResp); err != nil {
			return nil, fmt.Errorf("unable to translate Vault response data: %w", err)
		}

		if tokenResp.AccessToken == "" {
			return nil, fmt.Errorf("access_token missing in Vault response")
		}

		return &tokenResp, nil
	}

	return nil, fmt.Errorf("azure credential not yet accepted after %d attempts; "+
		"the client secret may still be propagating across Azure AD", maxRetries)
}
