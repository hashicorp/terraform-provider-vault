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

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ ephemeral.EphemeralResource = &DBEphemeralSecretResource{}

// NewDBEphemeralSecretResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewDBEphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &DBEphemeralSecretResource{}
}

// DBEphemeralSecretResource implements the methods that define this resource
type DBEphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

// DBEphemeralSecretModel describes the Terraform resource data model to match the
// resource schema.
type DBEphemeralSecretModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Mount             types.String `tfsdk:"mount"`
	Name              types.String `tfsdk:"name"`
	Username          types.String `tfsdk:"username"`
	Password          types.String `tfsdk:"password"`
	RSAPrivateKey     types.String `tfsdk:"rsa_private_key"`
	ClientCertificate types.String `tfsdk:"client_certificate"`
	PrivateKey        types.String `tfsdk:"private_key"`
	PrivateKeyType    types.String `tfsdk:"private_key_type"`
}

// DBEphemeralSecretAPIModel describes the Vault API data model.
type DBEphemeralSecretAPIModel struct {
	Username          string `json:"username" mapstructure:"username"`
	Password          string `json:"password" mapstructure:"password"`
	RSAPrivateKey     string `json:"rsa_private_key" mapstructure:"rsa_private_key"`
	ClientCertificate string `json:"client_certificate" mapstructure:"client_certificate"`
	PrivateKey        string `json:"private_key" mapstructure:"private_key"`
	PrivateKeyType    string `json:"private_key_type" mapstructure:"private_key_type"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *DBEphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the DB engine in Vault.",
				Required:            true,
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: " Specifies the name of the role to create credentials against.",
				Required:            true,
			},
			consts.FieldUsername: schema.StringAttribute{
				MarkdownDescription: "Username for the newly created DB user.",
				Computed:            true,
			},
			consts.FieldPassword: schema.StringAttribute{
				MarkdownDescription: "Password for the newly created DB user.",
				Computed:            true,
			},
			consts.FieldRSAPrivateKey: schema.StringAttribute{
				MarkdownDescription: "RSA private key for the newly created DB user. Only returned when credential_type is 'rsa_private_key'.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldClientCertificate: schema.StringAttribute{
				MarkdownDescription: "Client certificate for the newly created DB user. Only returned when credential_type is 'client_certificate'.",
				Computed:            true,
			},
			consts.FieldPrivateKey: schema.StringAttribute{
				MarkdownDescription: "Private key for the newly created DB user. Only returned when credential_type is 'client_certificate'.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldPrivateKeyType: schema.StringAttribute{
				MarkdownDescription: "Type of private key (e.g., 'rsa', 'ec'). Only returned when credential_type is 'client_certificate'.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to read a DB Secret from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *DBEphemeralSecretResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_database_secret"
}

func (r *DBEphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data DBEphemeralSecretModel
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

	path := r.path(data.Mount.ValueString(), data.Name.ValueString())

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

	var readResp DBEphemeralSecretAPIModel
	err = model.ToAPIModel(secretResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Set username (always present)
	data.Username = types.StringValue(readResp.Username)

	// Set credential fields based on what's returned
	if readResp.Password != "" {
		data.Password = types.StringValue(readResp.Password)
	}
	if readResp.RSAPrivateKey != "" {
		data.RSAPrivateKey = types.StringValue(readResp.RSAPrivateKey)
	}
	if readResp.ClientCertificate != "" {
		data.ClientCertificate = types.StringValue(readResp.ClientCertificate)
	}
	if readResp.PrivateKey != "" {
		data.PrivateKey = types.StringValue(readResp.PrivateKey)
	}
	if readResp.PrivateKeyType != "" {
		data.PrivateKeyType = types.StringValue(readResp.PrivateKeyType)
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *DBEphemeralSecretResource) path(mount, roleName string) string {
	return fmt.Sprintf("/%s/creds/%s", mount, roleName)
}
