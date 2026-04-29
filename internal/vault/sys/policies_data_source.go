// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ datasource.DataSource = &policiesDataSource{}
var _ datasource.DataSourceWithConfigure = &policiesDataSource{}

type policiesDataSourceModel struct {
	base.BaseModel

	NameFilter types.String `tfsdk:"name_filter"`
	Policies   types.List   `tfsdk:"policies"`
}

func NewPoliciesDataSource() datasource.DataSource {
	return &policiesDataSource{}
}

type policiesDataSource struct {
	base.DataSourceWithConfigure
}

func (d *policiesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policies"
}

func (d *policiesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists ACL policy names from Vault, with optional regex filtering.",
		Attributes: map[string]schema.Attribute{
			consts.FieldNameFilter: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A regex to filter policy names. Only names matching the pattern are returned.",
			},
			consts.FieldPolicies: schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "List of ACL policy names.",
			},
			consts.FieldNamespace: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Target namespace. (requires Enterprise)",
			},
		},
	}
}

func (d *policiesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data policiesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var filter *regexp.Regexp
	if !data.NameFilter.IsNull() && !data.NameFilter.IsUnknown() {
		var err error
		filter, err = regexp.Compile(data.NameFilter.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Invalid name_filter",
				"name_filter must be a valid regular expression: "+err.Error(),
			)
			return
		}
	}

	cli, err := client.GetClient(ctx, d.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultResp, err := cli.Logical().ListWithContext(ctx, "sys/policies/acl")
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	var names []string
	if vaultResp != nil {
		if keys, ok := vaultResp.Data["keys"].([]interface{}); ok {
			for _, k := range keys {
				name, ok := k.(string)
				if !ok {
					continue
				}
				if filter == nil || filter.MatchString(name) {
					names = append(names, name)
				}
			}
		}
	}

	policies, diags := types.ListValueFrom(ctx, types.StringType, names)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Policies = policies
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
