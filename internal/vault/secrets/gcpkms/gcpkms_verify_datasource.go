// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

// Ensure the implementation satisfies the datasource.DataSource interface
var _ datasource.DataSource = &GCPKMSVerifyDataSource{}

// NewGCPKMSVerifyDataSource returns the implementation for this data source
func NewGCPKMSVerifyDataSource() datasource.DataSource {
	return &GCPKMSVerifyDataSource{}
}

// GCPKMSVerifyDataSource implements the methods that define this data source
type GCPKMSVerifyDataSource struct {
	base.DataSourceWithConfigure
}

// GCPKMSVerifyModel describes the Terraform data source data model
type GCPKMSVerifyModel struct {
	base.BaseModelLegacy

	Backend    types.String `tfsdk:"backend"`
	Name       types.String `tfsdk:"name"`
	Digest     types.String `tfsdk:"digest"`
	Signature  types.String `tfsdk:"signature"`
	KeyVersion types.Int64  `tfsdk:"key_version"`
	Valid      types.Bool   `tfsdk:"valid"`
}

func (d *GCPKMSVerifyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcpkms_verify"
}

func (d *GCPKMSVerifyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldNamespace: schema.StringAttribute{
				MarkdownDescription: "Target namespace.",
				Optional:            true,
			},
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "Path where GCP KMS backend is mounted.",
				Required:            true,
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the key to use for verification.",
				Required:            true,
			},
			consts.FieldDigest: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded digest to verify.",
				Required:            true,
			},
			consts.FieldSignature: schema.StringAttribute{
				MarkdownDescription: "Base64-encoded signature to verify.",
				Required:            true,
			},
			consts.FieldKeyVersion: schema.Int64Attribute{
				MarkdownDescription: "Version of the key to use for verification.",
				Required:            true,
			},
			consts.FieldValid: schema.BoolAttribute{
				MarkdownDescription: "Whether the signature is valid.",
				Computed:            true,
			},
			consts.FieldID: schema.StringAttribute{
				MarkdownDescription: "Unique identifier for this data source.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Verifies a signature using a GCP KMS key in Vault.",
	}
}

func (d *GCPKMSVerifyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data GCPKMSVerifyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, d.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	name := data.Name.ValueString()
	verifyPath := fmt.Sprintf("%s/verify/%s", backend, name)

	requestData := map[string]interface{}{
		"digest":    data.Digest.ValueString(),
		"signature": data.Signature.ValueString(),
	}

	if !data.KeyVersion.IsNull() {
		requestData["key_version"] = data.KeyVersion.ValueInt64()
	}

	log.Printf("[DEBUG] Verifying signature with GCP KMS at %q", verifyPath)
	secret, err := cli.Logical().WriteWithContext(ctx, verifyPath, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error verifying signature",
			fmt.Sprintf("Error verifying signature at path %q: %s", verifyPath, err),
		)
		return
	}

	if secret == nil {
		resp.Diagnostics.AddError(
			"No response from verification endpoint",
			fmt.Sprintf("No response from verification endpoint at path %q", verifyPath),
		)
		return
	}

	valid := false
	if v, ok := secret.Data["valid"].(bool); ok {
		valid = v
	}

	data.Valid = types.BoolValue(valid)
	data.ID = types.StringValue(fmt.Sprintf("%s/%s/verify", backend, name))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
