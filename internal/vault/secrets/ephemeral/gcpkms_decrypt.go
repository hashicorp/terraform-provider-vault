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
)

var _ ephemeral.EphemeralResource = &GCPKMSDecryptEphemeralResource{}

var NewGCPKMSDecryptEphemeralResource = func() ephemeral.EphemeralResource {
	return &GCPKMSDecryptEphemeralResource{}
}

type GCPKMSDecryptEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

type GCPKMSDecryptModel struct {
	base.BaseModelEphemeral

	Backend                     types.String `tfsdk:"backend"`
	Name                        types.String `tfsdk:"name"`
	Ciphertext                  types.String `tfsdk:"ciphertext"`
	AdditionalAuthenticatedData types.String `tfsdk:"additional_authenticated_data"`
	KeyVersion                  types.Int64  `tfsdk:"key_version"`

	// Computed
	Plaintext types.String `tfsdk:"plaintext"`
}

func (r *GCPKMSDecryptEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "Path where GCP KMS backend is mounted",
				Required:            true,
			}, consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the key to use for decryption",
				Required:            true,
			},
			consts.FieldCiphertext: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded ciphertext to decrypt",
				Required:            true,
				Sensitive:           true,
			},
			consts.FieldAdditionalAuthenticatedData: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded additional authenticated data",
				Optional:            true,
			},
			consts.FieldKeyVersion: schema.Int64Attribute{
				MarkdownDescription: "Version of the key to use for decryption",
				Optional:            true,
			},
			consts.FieldPlaintext: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded plaintext",
				Computed:            true,
				Sensitive:           true,
			},
		},
		MarkdownDescription: "Decrypts ciphertext using GCP KMS",
	}
	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (r *GCPKMSDecryptEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcpkms_decrypt"
}

func (r *GCPKMSDecryptEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GCPKMSDecryptModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := fmt.Sprintf("%s/decrypt/%s", data.Backend.ValueString(), data.Name.ValueString())

	requestData := map[string]interface{}{
		consts.FieldCiphertext: data.Ciphertext.ValueString(),
	}

	if !data.AdditionalAuthenticatedData.IsNull() {
		requestData[consts.FieldAdditionalAuthenticatedData] = data.AdditionalAuthenticatedData.ValueString()
	}

	if !data.KeyVersion.IsNull() {
		requestData[consts.FieldKeyVersion] = data.KeyVersion.ValueInt64()
	}

	secret, err := c.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error decrypting with Vault",
			fmt.Sprintf("Error decrypting with GCP KMS at path %q: %s", path, err),
		)
		return
	}

	if secret == nil {
		resp.Diagnostics.AddError(
			"No response from decryption endpoint",
			fmt.Sprintf("No response from decryption endpoint at path %q", path),
		)
		return
	}

	if plaintext, ok := secret.Data[consts.FieldPlaintext]; ok {
		data.Plaintext = types.StringValue(plaintext.(string))
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
