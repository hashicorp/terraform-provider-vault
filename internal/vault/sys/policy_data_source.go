// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

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

var _ datasource.DataSource = &policyDataSource{}
var _ datasource.DataSourceWithConfigure = &policyDataSource{}

type policyDataSourceModel struct {
	base.BaseModel

	Name   types.String `tfsdk:"name"`
	Policy types.String `tfsdk:"policy"`
}

func NewPolicyDataSource() datasource.DataSource {
	return &policyDataSource{}
}

type policyDataSource struct {
	base.DataSourceWithConfigure
}

func (d *policyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (d *policyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads an ACL policy from Vault.",
		Attributes: map[string]schema.Attribute{
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the policy.",
			},
			consts.FieldPolicy: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The policy document.",
			},
			consts.FieldNamespace: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Target namespace. (requires Enterprise)",
			},
		},
	}
}

func (d *policyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data policyDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, d.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	name := data.Name.ValueString()

	vaultResp, err := cli.Logical().ReadWithContext(ctx, fmt.Sprintf("sys/policy/%s", name))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError("Policy Not Found", fmt.Sprintf("policy %q does not exist in Vault", name))
		return
	}

	rules, _ := vaultResp.Data["rules"].(string)
	data.Policy = types.StringValue(rules)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
