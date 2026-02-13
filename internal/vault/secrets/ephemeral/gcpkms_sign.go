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

var _ ephemeral.EphemeralResource = &GCPKMSSignEphemeralResource{}

var NewGCPKMSSignEphemeralResource = func() ephemeral.EphemeralResource {
	return &GCPKMSSignEphemeralResource{}
}

type GCPKMSSignEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

type GCPKMSSignModel struct {
	base.BaseModelEphemeral

	Backend    types.String `tfsdk:"backend"`
	Name       types.String `tfsdk:"name"`
	Digest     types.String `tfsdk:"digest"`
	KeyVersion types.Int64  `tfsdk:"key_version"`

	// Computed
	Signature types.String `tfsdk:"signature"`
}

func (r *GCPKMSSignEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "Path where GCP KMS backend is mounted",
				Required:            true,
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the key to use for signing",
				Required:            true,
			},
			consts.FieldDigest: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded digest to sign",
				Required:            true,
			},
			consts.FieldKeyVersion: schema.Int64Attribute{
				MarkdownDescription: "Version of the key to use for signing",
				Required:            true,
			},
			consts.FieldSignature: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded signature",
				Computed:            true,
			},
		},
		MarkdownDescription: "Signs a digest using GCP KMS",
	}
	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (r *GCPKMSSignEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcpkms_sign"
}

func (r *GCPKMSSignEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GCPKMSSignModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := fmt.Sprintf("%s/sign/%s", data.Backend.ValueString(), data.Name.ValueString())

	requestData := map[string]interface{}{
		"digest": data.Digest.ValueString(),
	}

	if !data.KeyVersion.IsNull() {
		requestData["key_version"] = data.KeyVersion.ValueInt64()
	}

	secret, err := c.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error signing with Vault",
			fmt.Sprintf("Error signing with GCP KMS at path %q: %s", path, err),
		)
		return
	}

	if secret == nil {
		resp.Diagnostics.AddError(
			"No response from signing endpoint",
			fmt.Sprintf("No response from signing endpoint at path %q", path),
		)
		return
	}

	if signature, ok := secret.Data["signature"]; ok {
		data.Signature = types.StringValue(signature.(string))
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
