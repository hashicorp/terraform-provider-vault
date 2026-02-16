// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ resource.Resource = &KeyRotateResource{}
var _ resource.ResourceWithImportState = &KeyRotateResource{}

type KeyRotateResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type KeyRotateResourceModel struct {
	base.BaseModelLegacy
	Path          types.String `tfsdk:"path"`
	Name          types.String `tfsdk:"name"`
	LatestVersion types.Int64  `tfsdk:"latest_version"`
}

func NewKeyRotateResource() resource.Resource {
	return &KeyRotateResource{}
}

func (r *KeyRotateResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keymgmt_key_rotate"
}

func (r *KeyRotateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Rotates a Key Management key",

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
				MarkdownDescription: "Name of the key to rotate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldLatestVersion: schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Latest version of the key after rotation",
			},
		},
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

func (r *KeyRotateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KeyRotateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := buildKeyRotatePath(vaultPath, name)

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, map[string]interface{}{}); err != nil {
		resp.Diagnostics.AddError("Error rotating Key Management key", fmt.Sprintf("Error rotating key at %s: %s", apiPath, err))
		return
	}

	keyPath := buildKeyPath(vaultPath, name)
	data.ID = types.StringValue(keyPath)

	r.read(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyRotateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KeyRotateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
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

func (r *KeyRotateResource) read(ctx context.Context, cli *api.Client, data *KeyRotateResourceModel, diags *diag.Diagnostics) {
	keyPath := data.ID.ValueString()
	vaultResp, err := cli.Logical().ReadWithContext(ctx, keyPath)
	if err != nil {
		diags.AddError("Error reading Key Management key", fmt.Sprintf("Error reading key at %s: %s", keyPath, err))
		return
	}

	if vaultResp == nil {
		data.ID = types.StringNull()
		return
	}

	parts := strings.Split(strings.Trim(keyPath, "/"), "/")
	keyIndex := -1
	for i, part := range parts {
		if part == "key" {
			keyIndex = i
			break
		}
	}

	if keyIndex == -1 || keyIndex >= len(parts)-1 {
		diags.AddError("Invalid path structure", fmt.Sprintf("Invalid key path: %s", keyPath))
		return
	}

	data.Path = types.StringValue(strings.Join(parts[:keyIndex], "/"))
	data.Name = types.StringValue(parts[keyIndex+1])

	// Always set latest_version to ensure it's known after apply
	latestVersionSet := false
	if v, ok := vaultResp.Data["latest_version"]; ok && v != nil {
		switch version := v.(type) {
		case float64:
			data.LatestVersion = types.Int64Value(int64(version))
			latestVersionSet = true
		case int:
			data.LatestVersion = types.Int64Value(int64(version))
			latestVersionSet = true
		case int64:
			data.LatestVersion = types.Int64Value(version)
			latestVersionSet = true
		case json.Number:
			if i, err := version.Int64(); err == nil {
				data.LatestVersion = types.Int64Value(i)
				latestVersionSet = true
			}
		}
	}

	// If latest_version was not successfully set, use a default value
	if !latestVersionSet {
		data.LatestVersion = types.Int64Value(1)
	}
}

func (r *KeyRotateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "Key rotation resource does not support updates")
}

func (r *KeyRotateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Key rotation is permanent in Vault
	// Removing it from Terraform state is sufficient
}

func buildKeyRotatePath(mountPath, name string) string {
	return strings.Trim(mountPath, "/") + "/key/" + name + "/rotate"
}
