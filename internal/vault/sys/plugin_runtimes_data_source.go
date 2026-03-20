// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var _ datasource.DataSource = &pluginRuntimesDataSource{}
var _ datasource.DataSourceWithConfigure = &pluginRuntimesDataSource{}

type pluginRuntimeModel struct {
	Name         types.String `tfsdk:"name"`
	Type         types.String `tfsdk:"type"`
	Rootless     types.Bool   `tfsdk:"rootless"`
	OCIRuntime   types.String `tfsdk:"oci_runtime"`
	CgroupParent types.String `tfsdk:"cgroup_parent"`
	CPUNanos     types.Int64  `tfsdk:"cpu_nanos"`
	MemoryBytes  types.Int64  `tfsdk:"memory_bytes"`
}

type pluginRuntimesDataSourceModel struct {
	base.BaseModel

	Type     types.String `tfsdk:"type"`
	ID       types.String `tfsdk:"id"`
	Runtimes types.List   `tfsdk:"runtimes"`
}

func NewPluginRuntimesDataSource() datasource.DataSource {
	return &pluginRuntimesDataSource{}
}

type pluginRuntimesDataSource struct {
	base.DataSourceWithConfigure
}

func (d *pluginRuntimesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plugin_runtimes"
}

func (d *pluginRuntimesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldType: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Specifies the plugin runtime type to list. Currently only `container` is supported.",
			},
			"runtimes": schema.ListAttribute{
				Computed:            true,
				MarkdownDescription: "List of plugin runtimes.",
				ElementType: types.ObjectType{AttrTypes: map[string]attr.Type{
					"name":          types.StringType,
					"type":          types.StringType,
					"rootless":      types.BoolType,
					"oci_runtime":   types.StringType,
					"cgroup_parent": types.StringType,
					"cpu_nanos":     types.Int64Type,
					"memory_bytes":  types.Int64Type,
				}},
			},
			consts.FieldID: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier for this data source.",
			},
			consts.FieldNamespace: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Target namespace. (requires Enterprise)",
			},
		},
		MarkdownDescription: "Lists plugin runtimes registered in Vault's plugin runtimes catalog.",
	}
}

func (d *pluginRuntimesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data pluginRuntimesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, d.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if !provider.IsAPISupported(d.Meta(), provider.VaultVersion115) {
		resp.Diagnostics.AddError("Unsupported Vault Version", "plugin runtimes require Vault 1.15 or later")
		return
	}

	path := "sys/plugins/runtimes/catalog"
	if !data.Type.IsNull() && !data.Type.IsUnknown() {
		path = fmt.Sprintf("%s?type=%s", path, data.Type.ValueString())
	}

	vaultResp, err := cli.Logical().ListWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError("Error Listing Plugin Runtimes", err.Error())
		return
	}

	var parsedRuntimes []pluginRuntimeModel

	if vaultResp != nil && vaultResp.Data != nil {
		if rawRuntimes, ok := vaultResp.Data["runtimes"].([]interface{}); ok {
			for _, elem := range rawRuntimes {
				if rMap, ok := elem.(map[string]interface{}); ok {
					rm := pluginRuntimeModel{}
					if name, ok := rMap["name"].(string); ok {
						rm.Name = types.StringValue(name)
					}
					if typ, ok := rMap["type"].(string); ok {
						rm.Type = types.StringValue(typ)
					}
					if rootless, ok := rMap["rootless"].(bool); ok {
						rm.Rootless = types.BoolValue(rootless)
					}
					if oci, ok := rMap["oci_runtime"].(string); ok && oci != "" {
						rm.OCIRuntime = types.StringValue(oci)
					}
					if cp, ok := rMap["cgroup_parent"].(string); ok && cp != "" {
						rm.CgroupParent = types.StringValue(cp)
					}
					if cn, ok := rMap["cpu_nanos"]; ok {
						if cnNum, ok := cn.(float64); ok { // JSON unmarshals numbers to float64
							if int64(cnNum) > 0 {
								rm.CPUNanos = types.Int64Value(int64(cnNum))
							}
						} else if cnNum, ok := cn.(int64); ok {
							if cnNum > 0 {
								rm.CPUNanos = types.Int64Value(cnNum)
							}
						}
					}
					if mb, ok := rMap["memory_bytes"]; ok {
						if mbNum, ok := mb.(float64); ok {
							if int64(mbNum) > 0 {
								rm.MemoryBytes = types.Int64Value(int64(mbNum))
							}
						} else if mbNum, ok := mb.(int64); ok {
							if mbNum > 0 {
								rm.MemoryBytes = types.Int64Value(mbNum)
							}
						}
					}
					parsedRuntimes = append(parsedRuntimes, rm)
				}
			}
		}
	}

	sort.Slice(parsedRuntimes, func(i, j int) bool {
		if parsedRuntimes[i].Type.ValueString() == parsedRuntimes[j].Type.ValueString() {
			return parsedRuntimes[i].Name.ValueString() < parsedRuntimes[j].Name.ValueString()
		}

		return parsedRuntimes[i].Type.ValueString() < parsedRuntimes[j].Type.ValueString()
	})

	idVal := "plugin-runtimes"
	if !data.Type.IsNull() {
		idVal = fmt.Sprintf("plugin-runtimes/%s", data.Type.ValueString())
	}
	data.ID = types.StringValue(idVal)

	listType := types.ObjectType{AttrTypes: map[string]attr.Type{
		"name":          types.StringType,
		"type":          types.StringType,
		"rootless":      types.BoolType,
		"oci_runtime":   types.StringType,
		"cgroup_parent": types.StringType,
		"cpu_nanos":     types.Int64Type,
		"memory_bytes":  types.Int64Type,
	}}

	runtimeObjs := make([]attr.Value, 0, len(parsedRuntimes))
	for _, m := range parsedRuntimes {
		obj, diags := types.ObjectValueFrom(ctx, listType.AttrTypes, m)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			runtimeObjs = append(runtimeObjs, obj)
		}
	}

	runtimesList, diags := types.ListValue(listType, runtimeObjs)
	resp.Diagnostics.Append(diags...)

	data.Runtimes = runtimesList

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
