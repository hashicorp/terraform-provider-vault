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

var _ ephemeral.EphemeralResource = &GCPKMSReencryptEphemeralResource{}

var NewGCPKMSReencryptEphemeralResource = func() ephemeral.EphemeralResource {
	return &GCPKMSReencryptEphemeralResource{}
}

type GCPKMSReencryptEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

type GCPKMSReencryptModel struct {
	base.BaseModelEphemeral

	Backend                     types.String `tfsdk:"backend"`
	Name                        types.String `tfsdk:"name"`
	Ciphertext                  types.String `tfsdk:"ciphertext"`
	AdditionalAuthenticatedData types.String `tfsdk:"additional_authenticated_data"`
	KeyVersion                  types.Int64  `tfsdk:"key_version"`

	// Computed
	NewCiphertext types.String `tfsdk:"new_ciphertext"`
}

func (r *GCPKMSReencryptEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "Path where GCP KMS backend is mounted",
				Required:            true,
			}, consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the key to use for re-encryption",
				Required:            true,
			},
			consts.FieldCiphertext: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded ciphertext to re-encrypt",
				Required:            true,
				Sensitive:           true,
			},
			consts.FieldAdditionalAuthenticatedData: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded additional authenticated data",
				Optional:            true,
			},
			consts.FieldKeyVersion: schema.Int64Attribute{
				MarkdownDescription: "Version of the key to use for re-encryption",
				Optional:            true,
			},
			consts.FieldNewCiphertext: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded re-encrypted ciphertext",
				Computed:            true,
				Sensitive:           true,
			},
		},
		MarkdownDescription: "Re-encrypts ciphertext using GCP KMS with the latest key version",
	}
	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (r *GCPKMSReencryptEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcpkms_reencrypt"
}

func (r *GCPKMSReencryptEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GCPKMSReencryptModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := fmt.Sprintf("%s/reencrypt/%s", data.Backend.ValueString(), data.Name.ValueString())

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
			"Error re-encrypting with Vault",
			fmt.Sprintf("Error re-encrypting with GCP KMS at path %q: %s", path, err),
		)
		return
	}

	if secret == nil {
		resp.Diagnostics.AddError(
			"No response from re-encryption endpoint",
			fmt.Sprintf("No response from re-encryption endpoint at path %q", path),
		)
		return
	}

	if ciphertext, ok := secret.Data[consts.FieldCiphertext]; ok {
		data.NewCiphertext = types.StringValue(ciphertext.(string))
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
