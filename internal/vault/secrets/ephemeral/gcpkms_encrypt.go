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

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &GCPKMSEncryptEphemeralResource{}

// NewGCPKMSEncryptEphemeralResource returns the implementation for this resource
var NewGCPKMSEncryptEphemeralResource = func() ephemeral.EphemeralResource {
	return &GCPKMSEncryptEphemeralResource{}
}

// GCPKMSEncryptEphemeralResource implements the ephemeral resource
type GCPKMSEncryptEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// GCPKMSEncryptModel describes the Terraform resource data model
type GCPKMSEncryptModel struct {
	base.BaseModelEphemeral

	Backend                     types.String `tfsdk:"backend"`
	Name                        types.String `tfsdk:"name"`
	Plaintext                   types.String `tfsdk:"plaintext"`
	AdditionalAuthenticatedData types.String `tfsdk:"additional_authenticated_data"`
	KeyVersion                  types.Int64  `tfsdk:"key_version"`

	// Computed
	Ciphertext types.String `tfsdk:"ciphertext"`
}

func (r *GCPKMSEncryptEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "Path where GCP KMS backend is mounted",
				Required:            true,
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the key to use for encryption",
				Required:            true,
			},
			consts.FieldPlaintext: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded plaintext to encrypt",
				Required:            true,
				Sensitive:           true,
			},
			consts.FieldAdditionalAuthenticatedData: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded additional authenticated data",
				Optional:            true,
			},
			consts.FieldKeyVersion: schema.Int64Attribute{
				MarkdownDescription: "Version of the key to use for encryption",
				Optional:            true,
			},
			consts.FieldCiphertext: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded ciphertext",
				Computed:            true,
				Sensitive:           true,
			},
		},
		MarkdownDescription: "Encrypts plaintext using GCP KMS",
	}
	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (r *GCPKMSEncryptEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcpkms_encrypt"
}

func (r *GCPKMSEncryptEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GCPKMSEncryptModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := fmt.Sprintf("%s/encrypt/%s", data.Backend.ValueString(), data.Name.ValueString())

	requestData := map[string]interface{}{
		consts.FieldPlaintext: data.Plaintext.ValueString(),
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
			"Error encrypting with Vault",
			fmt.Sprintf("Error encrypting with GCP KMS at path %q: %s", path, err),
		)
		return
	}

	if secret == nil {
		resp.Diagnostics.AddError(
			"No response from encryption endpoint",
			fmt.Sprintf("No response from encryption endpoint at path %q", path),
		)
		return
	}

	if ciphertext, ok := secret.Data[consts.FieldCiphertext]; ok {
		data.Ciphertext = types.StringValue(ciphertext.(string))
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
