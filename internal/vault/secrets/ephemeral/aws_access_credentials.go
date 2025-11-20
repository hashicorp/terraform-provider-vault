// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"fmt"
	"time"

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

var _ ephemeral.EphemeralResource = &AWSAccessCredentialsEphemeralSecretResource{}

var NewAWSAccessCredentialsEphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &AWSAccessCredentialsEphemeralSecretResource{}
}

type AWSAccessCredentialsEphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

type AWSAccessCredentialsEphemeralSecretModel struct {
	base.BaseModelEphemeral

	Mount   types.String `tfsdk:"mount"`
	Role    types.String `tfsdk:"role"`
	Type    types.String `tfsdk:"type"`
	RoleArn types.String `tfsdk:"role_arn"`
	Region  types.String `tfsdk:"region"`
	TTL     types.String `tfsdk:"ttl"`

	AccessKey      types.String `tfsdk:"access_key"`
	SecretKey      types.String `tfsdk:"secret_key"`
	SecurityToken  types.String `tfsdk:"security_token"`
	LeaseID        types.String `tfsdk:"lease_id"`
	LeaseDuration  types.Int64  `tfsdk:"lease_duration"`
	LeaseStartTime types.String `tfsdk:"lease_start_time"`
	LeaseRenewable types.Bool   `tfsdk:"lease_renewable"`
}

type AWSAccessCredentialsAPIModel struct {
	AccessKey     string `json:"access_key" mapstructure:"access_key"`
	SecretKey     string `json:"secret_key" mapstructure:"secret_key"`
	SecurityToken string `json:"security_token" mapstructure:"security_token"`
}

func (r *AWSAccessCredentialsEphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the AWS secret engine in Vault.",
				Required:            true,
			},
			consts.FieldRole: schema.StringAttribute{
				MarkdownDescription: "AWS Secret Role to read credentials from.",
				Required:            true,
			},
			consts.FieldType: schema.StringAttribute{
				MarkdownDescription: "Type of credentials to read. Must be either 'creds' for Access Key and Secret Key, or 'sts' for STS.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldRoleArn: schema.StringAttribute{
				MarkdownDescription: "ARN to use if multiple are available in the role. Required if the role has multiple ARNs.",
				Optional:            true,
			},
			consts.FieldRegion: schema.StringAttribute{
				MarkdownDescription: "Region the read credentials belong to.",
				Optional:            true,
			},
			consts.FieldTTL: schema.StringAttribute{
				MarkdownDescription: "User specified Time-To-Live for the STS token. Uses the Role defined default_sts_ttl when not specified.",
				Optional:            true,
			},
			consts.FieldAccessKey: schema.StringAttribute{
				MarkdownDescription: "AWS access key ID read from Vault.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldSecretKey: schema.StringAttribute{
				MarkdownDescription: "AWS secret key read from Vault.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldSecurityToken: schema.StringAttribute{
				MarkdownDescription: "AWS security token read from Vault. (Only returned if type is 'sts').",
				Computed:            true,
				Sensitive:           true,
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
		MarkdownDescription: "Provides an ephemeral resource to generate AWS credentials from Vault.",
	}
	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (r *AWSAccessCredentialsEphemeralSecretResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_access_credentials"
}

func (r *AWSAccessCredentialsEphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data AWSAccessCredentialsEphemeralSecretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Default type to "creds" if not specified
	credType := "creds"
	if !data.Type.IsNull() && !data.Type.IsUnknown() {
		credType = data.Type.ValueString()
	}

	// Build path
	path := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), credType, data.Role.ValueString())

	// Build request data based on credential type
	var sec *api.Secret

	if credType == "sts" {
		// For STS, use POST method (WriteWithContext) with map[string]interface{}
		writeData := make(map[string]interface{})

		if !data.RoleArn.IsNull() && !data.RoleArn.IsUnknown() && data.RoleArn.ValueString() != "" {
			writeData["role_arn"] = data.RoleArn.ValueString()
		}
		if !data.TTL.IsNull() && !data.TTL.IsUnknown() && data.TTL.ValueString() != "" {
			writeData["ttl"] = data.TTL.ValueString()
		}
		if !data.Region.IsNull() && !data.Region.IsUnknown() && data.Region.ValueString() != "" {
			writeData["region"] = data.Region.ValueString()
		}

		sec, err = c.Logical().WriteWithContext(ctx, path, writeData)
	} else {
		// For creds, use GET method (ReadWithContext) with map[string][]string
		requestData := map[string][]string{}

		if !data.RoleArn.IsNull() && !data.RoleArn.IsUnknown() && data.RoleArn.ValueString() != "" {
			requestData["role_arn"] = []string{data.RoleArn.ValueString()}
		}
		if !data.TTL.IsNull() && !data.TTL.IsUnknown() && data.TTL.ValueString() != "" {
			requestData["ttl"] = []string{data.TTL.ValueString()}
		}
		if !data.Region.IsNull() && !data.Region.IsUnknown() && data.Region.ValueString() != "" {
			requestData["region"] = []string{data.Region.ValueString()}
		}

		if len(requestData) > 0 {
			sec, err = c.Logical().ReadWithDataWithContext(ctx, path, requestData)
		} else {
			sec, err = c.Logical().ReadWithContext(ctx, path)
		}
	}

	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if sec == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiResp AWSAccessCredentialsAPIModel
	if err := model.ToAPIModel(sec.Data, &apiResp); err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Set computed values
	data.Type = types.StringValue(credType)
	data.AccessKey = types.StringValue(apiResp.AccessKey)
	data.SecretKey = types.StringValue(apiResp.SecretKey)

	// Security token is only available for STS type
	data.SecurityToken = types.StringValue(apiResp.SecurityToken)

	data.LeaseID = types.StringValue(sec.LeaseID)
	data.LeaseDuration = types.Int64Value(int64(sec.LeaseDuration))
	data.LeaseStartTime = types.StringValue(time.Now().Format(time.RFC3339))
	data.LeaseRenewable = types.BoolValue(sec.Renewable)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
