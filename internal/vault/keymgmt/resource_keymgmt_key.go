// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ resource.Resource = &KeyResource{}
var _ resource.ResourceWithImportState = &KeyResource{}

type KeyResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type KeyResourceModel struct {
	base.BaseModelLegacy

	Path              types.String `tfsdk:"path"`
	Name              types.String `tfsdk:"name"`
	Type              types.String `tfsdk:"type"`
	DeletionAllowed   types.Bool   `tfsdk:"deletion_allowed"`
	ReplicaRegions    types.Set    `tfsdk:"replica_regions"`
	LatestVersion     types.Int64  `tfsdk:"latest_version"`
	MinEnabledVersion types.Int64  `tfsdk:"min_enabled_version"`
}

func NewKeyResource() resource.Resource {
	return &KeyResource{}
}

func (r *KeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keymgmt_key"
}

func (r *KeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Key Management key in Vault",

		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Path where the Key Management secrets engine is mounted",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the key",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldType: schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Type of the key. Valid values are: aes256-gcm96, rsa-2048, rsa-3072, rsa-4096, " +
					"ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519, hmac",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldDeletionAllowed: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "If set to true, the key can be deleted. Defaults to false",
			},
			consts.FieldReplicaRegions: schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "List of regions where the key should be replicated. AWS KMS only.",
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldLatestVersion: schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Latest version of the key",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldMinEnabledVersion: schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Minimum enabled version of the key",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
		},
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

func (r *KeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KeyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting client", err.Error())
		return
	}

	vaultPath := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := buildKeyPath(vaultPath, name)

	writeData := map[string]interface{}{
		"type": data.Type.ValueString(),
	}

	if !data.ReplicaRegions.IsNull() && !data.ReplicaRegions.IsUnknown() {
		var regions []string
		resp.Diagnostics.Append(data.ReplicaRegions.ElementsAs(ctx, &regions, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(regions) > 0 {
			writeData[consts.FieldReplicaRegions] = strings.Join(regions, ",")
		}
	}

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError("Error creating Key Management key", fmt.Sprintf("Error creating key at %s: %s", apiPath, err))
		return
	}

	data.ID = types.StringValue(apiPath)
	time.Sleep(500 * time.Millisecond)

	configData := map[string]interface{}{}
	if !data.DeletionAllowed.IsNull() && !data.DeletionAllowed.IsUnknown() {
		configData[consts.FieldDeletionAllowed] = data.DeletionAllowed.ValueBool()
	}

	if len(configData) > 0 {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, configData); err != nil {
			resp.Diagnostics.AddError("Error updating Key Management key config", fmt.Sprintf("Error updating key config at %s: %s", apiPath, err))
			return
		}
	}

	r.read(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting client", err.Error())
		return
	}

	r.read(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.ID.IsNull() {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyResource) read(ctx context.Context, cli *api.Client, data *KeyResourceModel, diags *diag.Diagnostics) {
	apiPath := data.ID.ValueString()
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		diags.AddError("Error reading Key Management key", fmt.Sprintf("Error reading key at %s: %s", apiPath, err))
		return
	}

	if vaultResp == nil {
		data.ID = types.StringNull()
		return
	}

	parts := strings.Split(strings.Trim(apiPath, "/"), "/")
	keyIndex := -1
	for i, part := range parts {
		if part == "key" {
			keyIndex = i
			break
		}
	}

	if keyIndex == -1 || keyIndex+1 >= len(parts) {
		diags.AddError("Invalid path structure", fmt.Sprintf("Invalid key path: %s", apiPath))
		return
	}

	data.Path = types.StringValue(strings.Join(parts[:keyIndex], "/"))
	data.Name = types.StringValue(parts[keyIndex+1])

	if v, ok := vaultResp.Data["type"].(string); ok {
		data.Type = types.StringValue(v)
	}
	if v, ok := vaultResp.Data[consts.FieldDeletionAllowed].(bool); ok {
		data.DeletionAllowed = types.BoolValue(v)
	}

	if v, ok := vaultResp.Data[consts.FieldLatestVersion]; ok {
		switch version := v.(type) {
		case json.Number:
			if vInt, err := version.Int64(); err == nil {
				data.LatestVersion = types.Int64Value(vInt)
			}
		case float64:
			data.LatestVersion = types.Int64Value(int64(version))
		case int:
			data.LatestVersion = types.Int64Value(int64(version))
		case int64:
			data.LatestVersion = types.Int64Value(version)
		}
	}

	if v, ok := vaultResp.Data[consts.FieldMinEnabledVersion]; ok {
		switch version := v.(type) {
		case json.Number:
			if vInt, err := version.Int64(); err == nil {
				data.MinEnabledVersion = types.Int64Value(vInt)
			}
		case float64:
			data.MinEnabledVersion = types.Int64Value(int64(version))
		case int:
			data.MinEnabledVersion = types.Int64Value(int64(version))
		case int64:
			data.MinEnabledVersion = types.Int64Value(version)
		}
	}
}

func (r *KeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state KeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	apiPath := plan.ID.ValueString()
	writeData := map[string]interface{}{}

	if !plan.DeletionAllowed.Equal(state.DeletionAllowed) {
		writeData[consts.FieldDeletionAllowed] = plan.DeletionAllowed.ValueBool()
	}

	if len(writeData) > 0 {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError("Error updating Key Management key", fmt.Sprintf("Error updating key at %s: %s", apiPath, err))
			return
		}
	}

	r.read(ctx, cli, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *KeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting client", err.Error())
		return
	}

	apiPath := data.ID.ValueString()
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError("Error deleting Key Management key", fmt.Sprintf("Error deleting key at %s: %s", apiPath, err))
		return
	}
}
