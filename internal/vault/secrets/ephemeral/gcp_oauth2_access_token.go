// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
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
	Mount               types.String `tfsdk:"mount"`
	Roleset             types.String `tfsdk:"roleset"`
	StaticAccount       types.String `tfsdk:"static_account"`
	ImpersonatedAccount types.String `tfsdk:"impersonated_account"`

	// computed fields
	Token          types.String `tfsdk:"token"`
	TokenTTL       types.Int64  `tfsdk:"token_ttl"`
	LeaseID        types.String `tfsdk:"lease_id"`
	LeaseDuration  types.Int64  `tfsdk:"lease_duration"`
	LeaseStartTime types.String `tfsdk:"lease_start_time"`
	LeaseRenewable types.Bool   `tfsdk:"lease_renewable"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
func (r *GCPOAuth2AccessTokenEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the GCP Secret Backend to read credentials from.",
				Required:            true,
			},
			consts.FieldRoleset: schema.StringAttribute{
				MarkdownDescription: "GCP Secret Roleset to generate OAuth2 access token for. Mutually exclusive with `static_account` and `impersonated_account`.",
				Optional:            true,
			},
			consts.FieldStaticAccount: schema.StringAttribute{
				MarkdownDescription: "GCP Secret Static Account to generate OAuth2 access token for. Mutually exclusive with `roleset` and `impersonated_account`.",
				Optional:            true,
			},
			consts.FieldImpersonatedAccount: schema.StringAttribute{
				MarkdownDescription: "GCP Secret Impersonated Account to generate OAuth2 access token for. Mutually exclusive with `roleset` and `static_account`.",
				Optional:            true,
			},
			consts.FieldToken: schema.StringAttribute{
				MarkdownDescription: "The OAuth2 access token.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldTokenTTL: schema.Int64Attribute{
				MarkdownDescription: "The TTL of the token in seconds.",
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
			consts.FieldLeaseStartTime: schema.StringAttribute{
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

	// Validate that exactly one of roleset, static_account, or impersonated_account is provided
	hasRoleset := !data.Roleset.IsNull() && data.Roleset.ValueString() != ""
	hasStaticAccount := !data.StaticAccount.IsNull() && data.StaticAccount.ValueString() != ""
	hasImpersonatedAccount := !data.ImpersonatedAccount.IsNull() && data.ImpersonatedAccount.ValueString() != ""

	// Count how many are provided
	providedCount := 0
	if hasRoleset {
		providedCount++
	}
	if hasStaticAccount {
		providedCount++
	}
	if hasImpersonatedAccount {
		providedCount++
	}

	if providedCount == 0 {
		resp.Diagnostics.AddError(
			"Missing required field",
			"One of 'roleset', 'static_account', or 'impersonated_account' must be provided",
		)
		return
	}

	if providedCount > 1 {
		resp.Diagnostics.AddError(
			"Conflicting fields",
			"Only one of 'roleset', 'static_account', or 'impersonated_account' can be provided, not multiple",
		)
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	var tokenPath string
	var resourceType string
	var resourceName string

	if hasRoleset {
		roleset := data.Roleset.ValueString()
		tokenPath = mount + "/roleset/" + roleset + "/token"
		resourceType = "roleset"
		resourceName = roleset
	} else if hasStaticAccount {
		staticAccount := data.StaticAccount.ValueString()
		tokenPath = mount + "/static-account/" + staticAccount + "/token"
		resourceType = "static account"
		resourceName = staticAccount
	} else {
		impersonatedAccount := data.ImpersonatedAccount.ValueString()
		tokenPath = mount + "/impersonated-account/" + impersonatedAccount + "/token"
		resourceType = "impersonated account"
		resourceName = impersonatedAccount
	}

	// Configure exponential backoff with max retries
	// Initial interval: 2s, Max interval: 30s, Max retries: 5
	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.InitialInterval = 2 * time.Second
	exponentialBackoff.MaxInterval = 30 * time.Second
	exponentialBackoff.MaxElapsedTime = 0 // No time limit, only retry count matters

	bo := backoff.WithMaxRetries(exponentialBackoff, 5)
	bo = backoff.WithContext(bo, ctx)

	var vaultSecret *api.Secret
	attemptCount := 0

	// Retry operation with exponential backoff
	operation := func() error {
		attemptCount++

		// Read the OAuth2 access token from Vault (GET request)
		secret, err := c.Logical().ReadWithContext(ctx, tokenPath)

		if err != nil {
			// Check if the error is retryable based on HTTP status code
			// Retry on 400 Bad Request - this typically indicates the resource isn't ready yet
			if respErr, ok := err.(*api.ResponseError); ok && respErr.StatusCode == http.StatusBadRequest {
				log.Printf("[DEBUG] Attempt %d failed for %s %q. Error: %s", attemptCount, resourceType, resourceName, err)
				return err
			}
			// Non-retryable error
			log.Printf("[DEBUG] Non-retryable error encountered for %s %q: %s", resourceType, resourceName, err)
			return backoff.Permanent(err)
		}

		if secret == nil {
			err := fmt.Errorf("no credentials found at path %q", tokenPath)
			// Nil response might indicate the resource isn't ready yet, so retry
			log.Printf("[DEBUG] Attempt %d failed for %s %q: no credentials found", attemptCount, resourceType, resourceName)
			return err
		}

		// Success
		vaultSecret = secret
		return nil
	}

	// Execute with retry and backoff
	retryErr := backoff.RetryNotify(operation, bo, func(err error, duration time.Duration) {
		log.Printf("[DEBUG] Retrying %s %q in %v after error: %s", resourceType, resourceName, duration, err)
	})

	// Handle final error after all retries
	if retryErr != nil {
		resp.Diagnostics.AddError(
			"Error reading from Vault",
			fmt.Sprintf("Error generating GCP OAuth2 access token from path %q after %d attempts: %s\n\n"+
				"This may indicate that the %s %q or its associated GCP service account is not yet fully created or configured. "+
				"Please ensure:\n"+
				"1. The %s exists in Vault at the specified backend\n"+
				"2. The GCP service account has been created and granted necessary permissions\n"+
				"3. There is sufficient time between creating the %s and requesting tokens\n"+
				"4. The Vault GCP secrets engine is properly configured",
				tokenPath, attemptCount, retryErr, resourceType, resourceName, resourceType, resourceType),
		)
		return
	}

	if vaultSecret == nil {
		resp.Diagnostics.AddError(
			"No credentials found",
			fmt.Sprintf("No credentials found at path %q after %d attempts.\n\n"+
				"This may indicate that the %s %q or its associated GCP service account is not yet fully created or configured. "+
				"Please ensure:\n"+
				"1. The %s exists in Vault at the specified backend\n"+
				"2. The GCP service account has been created and granted necessary permissions\n"+
				"3. There is sufficient time between creating the %s and requesting tokens\n"+
				"4. The Vault GCP secrets engine is properly configured",
				tokenPath, attemptCount, resourceType, resourceName, resourceType, resourceType),
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
	} else {
		// If token_ttl is not in the response data, set it to null
		data.TokenTTL = types.Int64Null()
	}

	// Set lease information
	// Only set lease_id if it's not empty
	if vaultSecret.LeaseID != "" {
		data.LeaseID = types.StringValue(vaultSecret.LeaseID)
	} else {
		data.LeaseID = types.StringNull()
	}

	data.LeaseDuration = types.Int64Value(int64(vaultSecret.LeaseDuration))
	data.LeaseStartTime = types.StringValue(time.Now().Format(time.RFC3339))
	data.LeaseRenewable = types.BoolValue(vaultSecret.Renewable)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
