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
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &AWSStaticAccessCredentialsEphemeralResource{}

// NewAWSStaticAccessCredentialsEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewAWSStaticAccessCredentialsEphemeralResource = func() ephemeral.EphemeralResource {
	return &AWSStaticAccessCredentialsEphemeralResource{}
}

// AWSStaticAccessCredentialsEphemeralResource implements the methods that define this resource
type AWSStaticAccessCredentialsEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// AWSStaticAccessCredentialsEphemeralModel describes the Terraform resource data model to match the
// resource schema.
type AWSStaticAccessCredentialsEphemeralModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Backend   types.String `tfsdk:"backend"`
	Name      types.String `tfsdk:"name"`
	AccessKey types.String `tfsdk:"access_key"`
	SecretKey types.String `tfsdk:"secret_key"`
}

// AWSStaticAccessCredentialsAPIModel describes the Vault API data model.
type AWSStaticAccessCredentialsAPIModel struct {
	AccessKey string `json:"access_key" mapstructure:"access_key"`
	SecretKey string `json:"secret_key" mapstructure:"secret_key"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *AWSStaticAccessCredentialsEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
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
			},
			consts.FieldSecretKey: schema.StringAttribute{
				MarkdownDescription: "AWS secret key read from Vault.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to read AWS static credentials from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *AWSStaticAccessCredentialsEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_static_access_credentials"
}

func (r *AWSStaticAccessCredentialsEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data AWSStaticAccessCredentialsEphemeralModel
	// Read Terraform configuration into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := r.path(data.Backend.ValueString(), data.Name.ValueString())

	secretResp, err := c.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)

		return
	}
	if secretResp == nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadResponseNil(),
		)

		return
	}

	var readResp AWSStaticAccessCredentialsAPIModel
	err = model.ToAPIModel(secretResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.AccessKey = types.StringValue(readResp.AccessKey)
	data.SecretKey = types.StringValue(readResp.SecretKey)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *AWSStaticAccessCredentialsEphemeralResource) path(backend, name string) string {
	return fmt.Sprintf("%s/static-creds/%s", backend, name)
}
