// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"fmt"

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

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ ephemeral.EphemeralResource = &AWSStaticAccessCredentialsEphemeralSecretResource{}

// NewAWSStaticAccessCredentialsEphemeralSecretResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewAWSStaticAccessCredentialsEphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &AWSStaticAccessCredentialsEphemeralSecretResource{}
}

// AWSStaticAccessCredentialsEphemeralSecretResource implements the methods that define this resource
type AWSStaticAccessCredentialsEphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

// AWSStaticAccessCredentialsEphemeralSecretModel describes the Terraform resource data model to match the
// resource schema.
type AWSStaticAccessCredentialsEphemeralSecretModel struct {
	base.BaseModelEphemeral

	Mount types.String `tfsdk:"mount"`
	Name  types.String `tfsdk:"name"`

	AccessKey types.String `tfsdk:"access_key"`
	SecretKey types.String `tfsdk:"secret_key"`
}

// AWSStaticAccessCredentialsAPIModel describes the Vault API data model .
type AWSStaticAccessCredentialsAPIModel struct {
	AccessKey string `json:"access_key" mapstructure:"access_key"`
	SecretKey string `json:"secret_key" mapstructure:"secret_key"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *AWSStaticAccessCredentialsEphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the AWS secret engine in Vault.",
				Required:            true,
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the static role.",
				Required:            true,
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
		},
		MarkdownDescription: "Provides an ephemeral resource to read AWS static credentials from Vault.",
	}
	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *AWSStaticAccessCredentialsEphemeralSecretResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_static_access_credentials"
}

// Open retrieves AWS static access credentials from Vault for the specified static role.
// This method is called when the ephemeral resource is accessed during a Terraform operation.
func (r *AWSStaticAccessCredentialsEphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data AWSStaticAccessCredentialsEphemeralSecretModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := fmt.Sprintf("%s/static-creds/%s", data.Mount.ValueString(), data.Name.ValueString())

	var secret *api.Secret
	secret, err = c.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiResp AWSStaticAccessCredentialsAPIModel
	if err := model.ToAPIModel(secret.Data, &apiResp); err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.AccessKey = types.StringValue(apiResp.AccessKey)
	data.SecretKey = types.StringValue(apiResp.SecretKey)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
