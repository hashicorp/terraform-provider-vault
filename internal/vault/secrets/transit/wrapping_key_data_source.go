// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var (
	_ datasource.DataSource              = &WrappingKeyDataSource{}
	_ datasource.DataSourceWithConfigure = &WrappingKeyDataSource{}
)

// NewWrappingKeyDataSource returns the implementation for this data source.
func NewWrappingKeyDataSource() datasource.DataSource {
	return &WrappingKeyDataSource{}
}

// WrappingKeyDataSource reads the public wrapping key of a Transit secrets
// engine mount. The key is used to wrap key material before a BYOK import.
type WrappingKeyDataSource struct {
	base.DataSourceWithConfigure
}

// WrappingKeyModel describes the Terraform data source data model.
type WrappingKeyModel struct {
	base.BaseModel

	Mount     types.String `tfsdk:"mount"`
	PublicKey types.String `tfsdk:"public_key"`
}

func (d *WrappingKeyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_transit_wrapping_key"
}

func (d *WrappingKeyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the public wrapping key of a Transit secrets engine mount. Use it to wrap key material " +
			"before importing it (BYOK).",
		Attributes: map[string]schema.Attribute{
			consts.FieldNamespace: schema.StringAttribute{
				MarkdownDescription: "Target namespace. (requires Enterprise)",
				Optional:            true,
			},
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path where the Transit secrets engine is mounted.",
				Required:            true,
			},
			consts.FieldPublicKey: schema.StringAttribute{
				MarkdownDescription: "The PEM-encoded 4096-bit RSA public wrapping key.",
				Computed:            true,
			},
		},
	}
}

func (d *WrappingKeyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data WrappingKeyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, d.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	p := wrappingKeyPath(data.Mount.ValueString())
	secret, err := cli.Logical().ReadWithContext(ctx, p)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil || secret.Data == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	publicKey, ok := secret.Data[consts.FieldPublicKey].(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Vault response",
			fmt.Sprintf("Response from %q did not contain a %q string.", p, consts.FieldPublicKey),
		)
		return
	}

	data.PublicKey = types.StringValue(publicKey)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
