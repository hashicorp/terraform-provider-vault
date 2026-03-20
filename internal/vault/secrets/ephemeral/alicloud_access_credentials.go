// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
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
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &AliCloudAccessCredentialsEphemeralResource{}
var _ ephemeral.EphemeralResourceWithClose = &AliCloudAccessCredentialsEphemeralResource{}

// NewAliCloudAccessCredentialsEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewAliCloudAccessCredentialsEphemeralResource = func() ephemeral.EphemeralResource {
	return &AliCloudAccessCredentialsEphemeralResource{}
}

// AliCloudAccessCredentialsEphemeralResource implements the methods that define this resource
type AliCloudAccessCredentialsEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// AliCloudAccessCredentialsModel describes the Terraform resource data model to match the
// resource schema.
type AliCloudAccessCredentialsModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Mount          types.String `tfsdk:"mount"`
	Role           types.String `tfsdk:"role"`
	AccessKey      types.String `tfsdk:"access_key"`
	SecretKey      types.String `tfsdk:"secret_key"`
	SecurityToken  types.String `tfsdk:"security_token"`
	Expiration     types.String `tfsdk:"expiration"`
	LeaseID        types.String `tfsdk:"lease_id"`
	LeaseDuration  types.Int64  `tfsdk:"lease_duration"`
	LeaseStartTime types.String `tfsdk:"lease_start_time"`
	LeaseRenewable types.Bool   `tfsdk:"lease_renewable"`
}

// AliCloudAccessCredentialsAPIModel describes the Vault API data model.
type AliCloudAccessCredentialsAPIModel struct {
	AccessKey     string `json:"access_key" mapstructure:"access_key"`
	SecretKey     string `json:"secret_key" mapstructure:"secret_key"`
	SecurityToken string `json:"security_token" mapstructure:"security_token"`
	Expiration    string `json:"expiration" mapstructure:"expiration"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *AliCloudAccessCredentialsEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the AliCloud secret engine in Vault.",
				Required:            true,
			},
			consts.FieldRole: schema.StringAttribute{
				MarkdownDescription: "AliCloud Secret Role to read credentials from.",
				Required:            true,
			},
			consts.FieldAccessKey: schema.StringAttribute{
				MarkdownDescription: "AliCloud access key ID read from Vault.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldSecretKey: schema.StringAttribute{
				MarkdownDescription: "AliCloud secret key read from Vault.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldSecurityToken: schema.StringAttribute{
				MarkdownDescription: "AliCloud security token read from Vault (STS credentials).",
				Computed:            true,
			},
			consts.FieldExpiration: schema.StringAttribute{
				MarkdownDescription: "Expiration time for the credentials.",
				Computed:            true,
			},
			consts.FieldLeaseID: schema.StringAttribute{
				MarkdownDescription: "Lease identifier assigned by Vault.",
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
		MarkdownDescription: "Provides an ephemeral resource to generate AliCloud credentials from Vault.",
	}
	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *AliCloudAccessCredentialsEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_alicloud_access_credentials"
}

// Open method reads AliCloud credentials from Vault.
func (r *AliCloudAccessCredentialsEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data AliCloudAccessCredentialsModel
	var mount string
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

	if !data.Mount.IsNull() && !data.Mount.IsUnknown() {
		mount = data.Mount.ValueString()
	}

	role := data.Role.ValueString()

	// Build path: /alicloud/creds/:role
	path := fmt.Sprintf("%s/creds/%s", mount, role)

	// Read credentials from Vault
	sec, err := c.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if sec == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiResp AliCloudAccessCredentialsAPIModel
	if err := model.ToAPIModel(sec.Data, &apiResp); err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Set computed values
	data.Mount = types.StringValue(mount)
	data.AccessKey = types.StringValue(apiResp.AccessKey)
	data.SecretKey = types.StringValue(apiResp.SecretKey)
	data.SecurityToken = types.StringValue(apiResp.SecurityToken)
	data.Expiration = types.StringValue(apiResp.Expiration)

	// Set lease information
	data.LeaseID = types.StringValue(sec.LeaseID)
	data.LeaseDuration = types.Int64Value(int64(sec.LeaseDuration))
	data.LeaseStartTime = types.StringValue(time.Now().Format(time.RFC3339))
	data.LeaseRenewable = types.BoolValue(sec.Renewable)

	// Store lease information in private data for cleanup in Close
	if sec.LeaseID != "" {
		privateData, err := json.Marshal(AliCloudAccessCredentialsPrivateData{
			LeaseID:   sec.LeaseID,
			Namespace: data.Namespace.ValueString(),
		})
		if err != nil {
			log.Printf("[WARN] Failed to marshal private data: %s", err)
		} else {
			resp.Private.SetKey(ctx, "lease_data", privateData)
		}
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

// AliCloudAccessCredentialsPrivateData stores lease information for cleanup
type AliCloudAccessCredentialsPrivateData struct {
	LeaseID   string `json:"lease_id"`
	Namespace string `json:"namespace"`
}

// Close revokes the credentials lease when the ephemeral resource is no longer needed
func (r *AliCloudAccessCredentialsEphemeralResource) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	privateBytes, diags := req.Private.GetKey(ctx, "lease_data")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If no private data, nothing to clean up
	if len(privateBytes) == 0 {
		return
	}

	var privateData AliCloudAccessCredentialsPrivateData
	if err := json.Unmarshal(privateBytes, &privateData); err != nil {
		log.Printf("[WARN] Failed to unmarshal private data: %s", err)
		return
	}

	if privateData.LeaseID == "" {
		// No lease to revoke
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), privateData.Namespace)
	if err != nil {
		resp.Diagnostics.AddError("Error configuring Vault client for revoke", err.Error())
		return
	}

	// Attempt to revoke the lease
	err = c.Sys().Revoke(privateData.LeaseID)
	if err != nil {
		// Log but do not fail resource close
		log.Printf("[WARN] Failed to revoke lease %q: %s", privateData.LeaseID, err)
	} else {
		log.Printf("[DEBUG] Successfully revoked lease %q", privateData.LeaseID)
	}
}
