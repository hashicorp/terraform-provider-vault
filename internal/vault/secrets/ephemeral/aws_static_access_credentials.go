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

var _ ephemeral.EphemeralResource = &AWSStaticAccessCredentialsEphemeralSecretResource{}

var NewAWSStaticAccessCredentialsEphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &AWSStaticAccessCredentialsEphemeralSecretResource{}
}

type AWSStaticAccessCredentialsEphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

type AWSStaticAccessCredentialsEphemeralSecretModel struct {
	base.BaseModelEphemeral

	Backend types.String `tfsdk:"backend"`
	Name    types.String `tfsdk:"name"`

	AccessKey types.String `tfsdk:"access_key"`
	SecretKey types.String `tfsdk:"secret_key"`
}

type AWSStaticAccessCredentialsAPIModel struct {
	AccessKey string `json:"access_key" mapstructure:"access_key"`
	SecretKey string `json:"secret_key" mapstructure:"secret_key"`
}

func (r *AWSStaticAccessCredentialsEphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "AWS Secret Backend to read credentials from.",
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

func (r *AWSStaticAccessCredentialsEphemeralSecretResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_static_access_credentials"
}

func (r *AWSStaticAccessCredentialsEphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data AWSStaticAccessCredentialsEphemeralSecretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := fmt.Sprintf("%s/static-creds/%s", data.Backend.ValueString(), data.Name.ValueString())

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
