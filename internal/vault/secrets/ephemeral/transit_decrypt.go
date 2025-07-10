// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"encoding/base64"
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

var _ ephemeral.EphemeralResource = &TransitDecryptEphemeralSecretResource{}

var NewTransitDecryptEphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &TransitDecryptEphemeralSecretResource{}
}

type TransitDecryptEphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

type TransitDecryptEphemeralSecretModel struct {
	base.BaseModelEphemeral

	Key        types.String `tfsdk:"key"`
	Backend    types.String `tfsdk:"backend"`
	Plaintext  types.String `tfsdk:"plaintext"`
	Context    types.String `tfsdk:"context"`
	Ciphertext types.String `tfsdk:"ciphertext"`
}

type TransitDecryptEphemeralSecretAPIModel struct {
	Plaintext string `json:"plaintext" mapstructure:"plaintext"`
}

func (r *TransitDecryptEphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldKey: schema.StringAttribute{
				MarkdownDescription: "Name of the decryption key to use.",
				Required:            true,
			},
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "The Transit secret backend the key belongs to.",
				Required:            true,
			},
			consts.FieldPlaintext: schema.StringAttribute{
				MarkdownDescription: "Decrypted plain text",
				Computed:            true,
			},
			consts.FieldContext: schema.StringAttribute{
				MarkdownDescription: "Specifies the context for key derivation",
				Optional:            true,
			},
			consts.FieldCiphertext: schema.StringAttribute{
				MarkdownDescription: "Transit encrypted cipher text.",
				Required:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to decrypt a ciphertext from Vault using transit.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (r *TransitDecryptEphemeralSecretResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_transit_decrypt"
}

func (r *TransitDecryptEphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data TransitDecryptEphemeralSecretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
	}

	path := r.path(data.Backend.ValueString(), data.Key.ValueString())

	payload := map[string]interface{}{
		"ciphertext": data.Ciphertext.ValueString(),
		"context":    base64.StdEncoding.EncodeToString([]byte(data.Context.ValueString())),
	}

	secretResp, err := c.Logical().WriteWithContext(ctx, path, payload)
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

	var decryptedResp TransitDecryptEphemeralSecretAPIModel
	err = model.ToAPIModel(secretResp.Data, &decryptedResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response Data", err.Error())
		return
	}

	plaintext, _ := base64.StdEncoding.DecodeString(decryptedResp.Plaintext)

	data.Plaintext = types.StringValue(string(plaintext))

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *TransitDecryptEphemeralSecretResource) path(backend, key string) string {
	return fmt.Sprintf("/%s/decrypt/%s", backend, key)
}
