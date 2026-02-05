// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var _ resource.Resource = &KeyResource{}
var _ resource.ResourceWithImportState = &KeyResource{}

type KeyResource struct {
	client *api.Client
}

type KeyResourceModel struct {
	ID                   types.String `tfsdk:"id"`
	Path                 types.String `tfsdk:"path"`
	Name                 types.String `tfsdk:"name"`
	Type                 types.String `tfsdk:"type"`
	DeletionAllowed      types.Bool   `tfsdk:"deletion_allowed"`
	AllowPlaintextBackup types.Bool   `tfsdk:"allow_plaintext_backup"`
	AllowGenerateKey     types.Bool   `tfsdk:"allow_generate_key"`
	ReplicaRegions       types.Set    `tfsdk:"replica_regions"`
	LatestVersion        types.Int64  `tfsdk:"latest_version"`
	MinEnabledVersion    types.Int64  `tfsdk:"min_enabled_version"`
	Distribution         types.List   `tfsdk:"distribution"`
}

type DistributionModel struct {
	KMS types.String `tfsdk:"kms"`
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
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
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
			"deletion_allowed": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "If set to true, the key can be deleted. Defaults to false",
			},
			"allow_plaintext_backup": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "If set to true, plaintext backup of the key is allowed. Defaults to false",
			},
			"allow_generate_key": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "If set to true, allows generating a new key in supported KMS providers. Defaults to true",
			},
			"replica_regions": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "List of regions where the key should be replicated. AWS KMS only.",
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"latest_version": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Latest version of the key",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"min_enabled_version": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Minimum enabled version of the key",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"distribution": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "List of KMS providers where this key is distributed",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"kms": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Name of the KMS provider",
						},
					},
				},
			},
		},
	}
}

func (r *KeyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerMeta, ok := req.ProviderData.(interface {
		Meta() interface{}
	})
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected provider metadata interface, got: %T", req.ProviderData),
		)
		return
	}

	meta := providerMeta.Meta()
	client, ok := meta.(*api.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Meta Type",
			fmt.Sprintf("Expected *api.Client, got: %T", meta),
		)
		return
	}

	r.client = client
}

func (r *KeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KeyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
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
			writeData["replica_regions"] = strings.Join(regions, ",")
		}
	}

	if _, err := r.client.Logical().Write(apiPath, writeData); err != nil {
		resp.Diagnostics.AddError("Error creating Key Management key", fmt.Sprintf("Error creating key at %s: %s", apiPath, err))
		return
	}

	data.ID = types.StringValue(apiPath)
	time.Sleep(500 * time.Millisecond)

	configData := map[string]interface{}{}
	if !data.DeletionAllowed.IsNull() && !data.DeletionAllowed.IsUnknown() {
		configData["deletion_allowed"] = data.DeletionAllowed.ValueBool()
	}
	if !data.AllowPlaintextBackup.IsNull() && !data.AllowPlaintextBackup.IsUnknown() {
		configData["allow_plaintext_backup"] = data.AllowPlaintextBackup.ValueBool()
	}
	if !data.AllowGenerateKey.IsNull() && !data.AllowGenerateKey.IsUnknown() {
		configData["allow_generate_key"] = data.AllowGenerateKey.ValueBool()
	}

	if len(configData) > 0 {
		if _, err := r.client.Logical().Write(apiPath, configData); err != nil {
			resp.Diagnostics.AddError("Error updating Key Management key config", fmt.Sprintf("Error updating key config at %s: %s", apiPath, err))
			return
		}
	}

	r.read(ctx, &data, &resp.Diagnostics)
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

	r.read(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.ID.IsNull() {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyResource) read(ctx context.Context, data *KeyResourceModel, diags *diag.Diagnostics) {
	apiPath := data.ID.ValueString()
	vaultResp, err := r.client.Logical().Read(apiPath)
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
	if v, ok := vaultResp.Data["deletion_allowed"].(bool); ok {
		data.DeletionAllowed = types.BoolValue(v)
	}
	if v, ok := vaultResp.Data["allow_plaintext_backup"].(bool); ok {
		data.AllowPlaintextBackup = types.BoolValue(v)
	}
	if v, ok := vaultResp.Data["allow_generate_key"].(bool); ok {
		data.AllowGenerateKey = types.BoolValue(v)
	}

	if v, ok := vaultResp.Data["latest_version"]; ok {
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

	if v, ok := vaultResp.Data["min_enabled_version"]; ok {
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

	if v, ok := vaultResp.Data["distribution"].([]interface{}); ok {
		var distModels []DistributionModel
		for _, dist := range v {
			if distMap, ok := dist.(map[string]interface{}); ok {
				if kms, ok := distMap["kms"].(string); ok {
					distModels = append(distModels, DistributionModel{KMS: types.StringValue(kms)})
				}
			}
		}
		listVal, d := types.ListValueFrom(ctx, types.ObjectType{
			AttrTypes: map[string]attr.Type{"kms": types.StringType},
		}, distModels)
		diags.Append(d...)
		if !diags.HasError() {
			data.Distribution = listVal
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

	apiPath := plan.ID.ValueString()
	writeData := map[string]interface{}{}

	if !plan.DeletionAllowed.Equal(state.DeletionAllowed) {
		writeData["deletion_allowed"] = plan.DeletionAllowed.ValueBool()
	}
	if !plan.AllowPlaintextBackup.Equal(state.AllowPlaintextBackup) {
		writeData["allow_plaintext_backup"] = plan.AllowPlaintextBackup.ValueBool()
	}
	if !plan.AllowGenerateKey.Equal(state.AllowGenerateKey) {
		writeData["allow_generate_key"] = plan.AllowGenerateKey.ValueBool()
	}

	if len(writeData) > 0 {
		if _, err := r.client.Logical().Write(apiPath, writeData); err != nil {
			resp.Diagnostics.AddError("Error updating Key Management key", fmt.Sprintf("Error updating key at %s: %s", apiPath, err))
			return
		}
	}

	r.read(ctx, &plan, &resp.Diagnostics)
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

	apiPath := data.ID.ValueString()
	if _, err := r.client.Logical().Delete(apiPath); err != nil {
		resp.Diagnostics.AddError("Error deleting Key Management key", fmt.Sprintf("Error deleting key at %s: %s", apiPath, err))
		return
	}
}

func (r *KeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
