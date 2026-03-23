// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	fieldOCIRuntime   = "oci_runtime"
	fieldCgroupParent = "cgroup_parent"
	fieldCPUNanos     = "cpu_nanos"
	fieldMemoryBytes  = "memory_bytes"
	fieldRootless     = "rootless"
)

var _ resource.Resource = &pluginRuntimeResourceFW{}
var _ resource.ResourceWithConfigure = &pluginRuntimeResourceFW{}
var _ resource.ResourceWithImportState = &pluginRuntimeResourceFW{}

type pluginRuntimeResourceModel struct {
	base.BaseModelLegacy

	Type         types.String `tfsdk:"type"`
	Name         types.String `tfsdk:"name"`
	Rootless     types.Bool   `tfsdk:"rootless"`
	OCIRuntime   types.String `tfsdk:"oci_runtime"`
	CgroupParent types.String `tfsdk:"cgroup_parent"`
	CPUNanos     types.Int64  `tfsdk:"cpu_nanos"`
	MemoryBytes  types.Int64  `tfsdk:"memory_bytes"`
}

func NewPluginRuntimeResource() resource.Resource {
	return &pluginRuntimeResourceFW{}
}

type pluginRuntimeResourceFW struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

func (r *pluginRuntimeResourceFW) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plugin_runtime"
}

func (r *pluginRuntimeResourceFW) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldType: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Specifies the plugin runtime type. Currently only `container` is supported.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("container"),
				},
			},
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the plugin runtime.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			fieldRootless: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the container runtime is running as a non-privileged user.",
			},
			fieldOCIRuntime: schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Specifies OCI-compliant container runtime to use.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			fieldCgroupParent: schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Specifies the parent cgroup to set for each container.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			fieldCPUNanos: schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Specifies CPU limit to set per container in billionths of a CPU.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			fieldMemoryBytes: schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Specifies memory limit to set per container in bytes.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
		},
		MarkdownDescription: "Manages a plugin runtime in Vault's plugin runtimes catalog.",
	}

	base.MustAddLegacyBaseSchema(&resp.Schema)
}

func (r *pluginRuntimeResourceFW) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data pluginRuntimeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if !provider.IsAPISupported(r.Meta(), provider.VaultVersion115) {
		resp.Diagnostics.AddError("Unsupported Vault Version", "plugin runtimes require Vault 1.15 or later")
		return
	}

	runType := data.Type.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("sys/plugins/runtimes/catalog/%s/%s", runType, name)

	payload := r.buildPayload(data)
	_, err = cli.Logical().WriteWithContext(ctx, path, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error Writing Plugin Runtime", err.Error())
		return
	}

	data.ID = types.StringValue(fmt.Sprintf("%s/%s", runType, name))

	// Ensure all optional computed fields are known (set to null if not configured)
	if data.OCIRuntime.IsUnknown() {
		data.OCIRuntime = types.StringNull()
	}
	if data.CgroupParent.IsUnknown() {
		data.CgroupParent = types.StringNull()
	}
	if data.CPUNanos.IsUnknown() {
		data.CPUNanos = types.Int64Null()
	}
	if data.MemoryBytes.IsUnknown() {
		data.MemoryBytes = types.Int64Null()
	}

	// Set the state with the planned values since the API doesn't return all fields
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *pluginRuntimeResourceFW) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data pluginRuntimeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	id := data.ID.ValueString()
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		resp.Diagnostics.AddError("Invalid ID", "Plugin runtime ID must be of format <type>/<name>")
		return
	}

	runType, name := parts[0], parts[1]
	path := fmt.Sprintf("sys/plugins/runtimes/catalog/%s/%s", runType, name)

	// Check if resource exists in Vault
	vaultResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		if util.Is404(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error Reading Plugin Runtime", err.Error())
		return
	}
	if vaultResp == nil || vaultResp.Data == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Update type and name from ID
	data.Type = types.StringValue(runType)
	data.Name = types.StringValue(name)

	// Read all fields from API response
	if v, ok := vaultResp.Data["rootless"].(bool); ok {
		data.Rootless = types.BoolValue(v)
	}

	// Read optional fields - set to null if not present in response
	if v, ok := vaultResp.Data["oci_runtime"].(string); ok && v != "" {
		data.OCIRuntime = types.StringValue(v)
	} else {
		data.OCIRuntime = types.StringNull()
	}

	if v, ok := vaultResp.Data["cgroup_parent"].(string); ok && v != "" {
		data.CgroupParent = types.StringValue(v)
	} else {
		data.CgroupParent = types.StringNull()
	}

	// Read all optional fields from API - util functions handle type conversion and null values
	// Note: Vault client may return json.Number type for numeric fields
	data.CPUNanos = util.Int64ValueOrNull(vaultResp.Data["cpu_nanos"])
	data.MemoryBytes = util.Int64ValueOrNull(vaultResp.Data["memory_bytes"])

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *pluginRuntimeResourceFW) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data pluginRuntimeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	runType := data.Type.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("sys/plugins/runtimes/catalog/%s/%s", runType, name)

	payload := r.buildPayload(data)
	_, err = cli.Logical().WriteWithContext(ctx, path, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Plugin Runtime", err.Error())
		return
	}

	// Ensure all optional computed fields are known (set to null if not configured)
	if data.OCIRuntime.IsUnknown() {
		data.OCIRuntime = types.StringNull()
	}
	if data.CgroupParent.IsUnknown() {
		data.CgroupParent = types.StringNull()
	}
	if data.CPUNanos.IsUnknown() {
		data.CPUNanos = types.Int64Null()
	}
	if data.MemoryBytes.IsUnknown() {
		data.MemoryBytes = types.Int64Null()
	}

	// Set the state with the planned values since the API doesn't return all fields
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *pluginRuntimeResourceFW) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data pluginRuntimeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	id := data.ID.ValueString()
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		resp.Diagnostics.AddError("Invalid ID", "Plugin runtime ID must be of format <type>/<name>")
		return
	}

	path := fmt.Sprintf("sys/plugins/runtimes/catalog/%s/%s", parts[0], parts[1])
	_, err = cli.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		if strings.Contains(err.Error(), "referenced by") || strings.Contains(err.Error(), "in use") {
			resp.Diagnostics.AddError("Cannot Delete Plugin Runtime", fmt.Sprintf("Runtime %q is in use or referenced by plugins: %s", data.Name.ValueString(), err.Error()))
		} else {
			resp.Diagnostics.AddError("Error Deleting Plugin Runtime", err.Error())
		}
		return
	}
}

func (r *pluginRuntimeResourceFW) buildPayload(data pluginRuntimeResourceModel) map[string]interface{} {
	payload := make(map[string]interface{})
	if !data.Rootless.IsNull() && !data.Rootless.IsUnknown() {
		payload[fieldRootless] = data.Rootless.ValueBool()
	}
	if !data.OCIRuntime.IsNull() && !data.OCIRuntime.IsUnknown() {
		payload[fieldOCIRuntime] = data.OCIRuntime.ValueString()
	}
	if !data.CgroupParent.IsNull() && !data.CgroupParent.IsUnknown() {
		payload[fieldCgroupParent] = data.CgroupParent.ValueString()
	}
	if !data.CPUNanos.IsNull() && !data.CPUNanos.IsUnknown() {
		payload[fieldCPUNanos] = data.CPUNanos.ValueInt64()
	}
	if !data.MemoryBytes.IsNull() && !data.MemoryBytes.IsUnknown() {
		payload[fieldMemoryBytes] = data.MemoryBytes.ValueInt64()
	}
	return payload
}
