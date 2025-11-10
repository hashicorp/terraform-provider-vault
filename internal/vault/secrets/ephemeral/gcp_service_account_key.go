// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
var _ ephemeral.EphemeralResource = &GCPServiceAccountKeyEphemeralResource{}

// NewGCPServiceAccountKeyEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewGCPServiceAccountKeyEphemeralResource = func() ephemeral.EphemeralResource {
	return &GCPServiceAccountKeyEphemeralResource{}
}

// GCPServiceAccountKeyEphemeralResource implements the methods that define this resource
type GCPServiceAccountKeyEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// GCPServiceAccountKeyModel describes the Terraform resource data model to match the
// resource schema.
type GCPServiceAccountKeyModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Backend       types.String `tfsdk:"backend"`
	Roleset       types.String `tfsdk:"roleset"`
	StaticAccount types.String `tfsdk:"static_account"`
	KeyAlgorithm  types.String `tfsdk:"key_algorithm"`
	KeyType       types.String `tfsdk:"key_type"`

	// computed fields
	PrivateKeyData      types.String `tfsdk:"private_key_data"`
	PrivateKeyType      types.String `tfsdk:"private_key_type"`
	ServiceAccountEmail types.String `tfsdk:"service_account_email"`
	LeaseID             types.String `tfsdk:"lease_id"`
	LeaseDuration       types.Int64  `tfsdk:"lease_duration"`
	LeaseStartTime      types.String `tfsdk:"lease_start_time"`
	LeaseRenewable      types.Bool   `tfsdk:"lease_renewable"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
func (r *GCPServiceAccountKeyEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"backend": schema.StringAttribute{
				MarkdownDescription: "GCP Secret Backend to read credentials from.",
				Required:            true,
			},
			"roleset": schema.StringAttribute{
				MarkdownDescription: "GCP Secret Roleset to generate credentials for. Mutually exclusive with `static_account`.",
				Optional:            true,
			},
			"static_account": schema.StringAttribute{
				MarkdownDescription: "GCP Secret Static Account to generate credentials for. Mutually exclusive with `roleset`.",
				Optional:            true,
			},
			"key_algorithm": schema.StringAttribute{
				MarkdownDescription: "Key algorithm used to generate key. Defaults to 2k RSA key. Accepted values: `KEY_ALG_UNSPECIFIED`, `KEY_ALG_RSA_1024`, `KEY_ALG_RSA_2048`.",
				Optional:            true,
			},
			"key_type": schema.StringAttribute{
				MarkdownDescription: "Private key type to generate. Defaults to JSON credentials file. Accepted values: `TYPE_UNSPECIFIED`, `TYPE_PKCS12_FILE`, `TYPE_GOOGLE_CREDENTIALS_FILE`.",
				Optional:            true,
			},
			"private_key_data": schema.StringAttribute{
				MarkdownDescription: "The private key data in JSON format.",
				Computed:            true,
				Sensitive:           true,
			},
			"private_key_type": schema.StringAttribute{
				MarkdownDescription: "The type of the private key.",
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
		MarkdownDescription: "Provides an ephemeral resource to generate GCP service account keys from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *GCPServiceAccountKeyEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcp_service_account_key"
}

func (r *GCPServiceAccountKeyEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GCPServiceAccountKeyModel
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
	var credsPath string

	if hasRoleset {
		roleset := data.Roleset.ValueString()
		credsPath = backend + "/key/" + roleset
	} else {
		staticAccount := data.StaticAccount.ValueString()
		credsPath = backend + "/static-account/" + staticAccount + "/key"
	}

	// Build request data
	requestData := map[string]interface{}{}
	if !data.KeyAlgorithm.IsNull() && data.KeyAlgorithm.ValueString() != "" {
		requestData["key_algorithm"] = data.KeyAlgorithm.ValueString()
	}
	if !data.KeyType.IsNull() && data.KeyType.ValueString() != "" {
		requestData["key_type"] = data.KeyType.ValueString()
	}

	// Use Write for generating the key (POST request)
	vaultSecret, readErr := c.Logical().WriteWithContext(ctx, credsPath, requestData)
	if readErr != nil {
		resp.Diagnostics.AddError(
			"Error reading from Vault",
			fmt.Sprintf("Error generating GCP service account key from path %q: %s", credsPath, readErr),
		)
		return
	}

	if vaultSecret == nil {
		resp.Diagnostics.AddError(
			"No credentials found",
			fmt.Sprintf("No credentials found at path %q", credsPath),
		)
		return
	}

	log.Printf("[DEBUG] Generated GCP service account key from %q", credsPath)

	// Extract private_key_data (base64-encoded from Vault)
	privateKeyDataB64, ok := vaultSecret.Data["private_key_data"].(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Invalid response from Vault",
			"private_key_data field not found or not a string in Vault response",
		)
		return
	}

	// Decode the base64-encoded private key data to get the actual JSON
	decodedKey, err := base64.StdEncoding.DecodeString(privateKeyDataB64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error decoding private key data",
			fmt.Sprintf("Failed to decode base64 private_key_data: %s", err),
		)
		return
	}

	// Store the decoded JSON string (not base64-encoded)
	jsonStr := string(decodedKey)
	log.Printf("[DEBUG] Decoded private_key_data length: %d bytes", len(jsonStr))
	log.Printf("[DEBUG] First 100 chars of decoded JSON: %s", jsonStr[:min(100, len(jsonStr))])
	data.PrivateKeyData = types.StringValue(jsonStr)

	// Set optional fields if present
	if keyType, ok := vaultSecret.Data["key_type"].(string); ok {
		data.PrivateKeyType = types.StringValue(keyType)
	}

	// Try to extract service account email from the JSON
	var keyData map[string]interface{}
	if err := json.Unmarshal(decodedKey, &keyData); err == nil {
		if email, ok := keyData["client_email"].(string); ok {
			data.ServiceAccountEmail = types.StringValue(email)
		}
	}

	data.LeaseID = types.StringValue(vaultSecret.LeaseID)
	data.LeaseDuration = types.Int64Value(int64(vaultSecret.LeaseDuration))
	data.LeaseStartTime = types.StringValue(time.Now().Format(time.RFC3339))
	data.LeaseRenewable = types.BoolValue(vaultSecret.Renewable)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
