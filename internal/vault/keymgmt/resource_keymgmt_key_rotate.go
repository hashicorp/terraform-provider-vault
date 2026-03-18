// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	vaultapi "github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ resource.Resource = &KeyRotateResource{}
var _ resource.ResourceWithImportState = &KeyRotateResource{}

type KeyRotateResource struct {
	base.ResourceWithConfigure
}

type KeyRotateResourceModel struct {
	base.BaseModel
	Mount         types.String `tfsdk:"mount"`
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
			consts.FieldMount: schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Path of the Key Management secrets engine mount. Must match the `path` of a `vault_mount` " +
					"resource with `type = \"keymgmt\"`. Use `vault_mount.keymgmt.path` here.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Specifies the name of the key to rotate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldLatestVersion: schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Specifies the latest version of the key.",
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *KeyRotateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KeyRotateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	rotatePath := BuildKeyRotatePath(data.Mount.ValueString(), data.Name.ValueString())
	if _, err := cli.Logical().WriteWithContext(ctx, rotatePath, map[string]interface{}{}); err != nil {
		resp.Diagnostics.AddError(ErrCreating(ResourceTypeKeyRotation, rotatePath, err))
		return
	}

	// Read back the key metadata to get latest_version
	responseData, exists := r.readKey(ctx, cli, data.KeyPath(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		resp.Diagnostics.AddError(
			"Unexpected error after rotating Key Management key",
			fmt.Sprintf("Key Management key not found at path %q immediately after rotation", data.KeyPath()),
		)
		return
	}

	// Parse response data
	data.parseKeyRotateResponse(responseData)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyRotateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KeyRotateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	// Build the key path and read key metadata
	keyPath := data.KeyPath()
	responseData, exists := r.readKey(ctx, cli, keyPath, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !exists {
		tflog.Warn(ctx, "Key Management key not found, removing from state", map[string]interface{}{
			"path": keyPath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// Parse response data
	data.parseKeyRotateResponse(responseData)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyRotateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "Key rotation resource does not support updates")
}

func (r *KeyRotateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Key rotation is permanent in Vault
	// Removing it from Terraform state is sufficient
}

func (r *KeyRotateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Validate import ID is not empty
	if req.ID == "" {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			"Import identifier cannot be empty. Expected format: '<mount_path>/key/<name>/rotate', "+
				"namespace can be specified using the env var "+consts.EnvVarVaultNamespaceImport,
		)
		return
	}

	// Parse the import ID - expect format: <mount_path>/key/<name>/rotate
	importID := req.ID
	// Ensure the path ends with "rotate"
	parts := strings.Split(strings.Trim(importID, "/"), "/")
	if len(parts) == 0 || parts[len(parts)-1] != "rotate" {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q must end with /rotate. Expected format: '<mount_path>/key/<name>/rotate', "+
				"namespace can be specified using the env var %s", importID, consts.EnvVarVaultNamespaceImport),
		)
		return
	}

	// Remove the "rotate" suffix to parse the base key path
	parts = parts[:len(parts)-1]
	keyPath := strings.Join(parts, "/")
	mountPath, keyName, err := ParseKeyPath(keyPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s. Expected format: '<mount_path>/key/<name>/rotate', "+
				"namespace can be specified using the env var %s", importID, err.Error(), consts.EnvVarVaultNamespaceImport),
		)
		return
	}

	// Set the individual fields in state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mountPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), keyName)...)

	// Handle namespace if needed
	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(
			resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}

// parseKeyRotateResponse parses the Vault API response data into the resource model
func (data *KeyRotateResourceModel) parseKeyRotateResponse(responseData map[string]interface{}) {
	// Only set latest_version when it is returned and can be parsed from the API response.
	if v, ok := responseData[consts.FieldLatestVersion]; ok && v != nil {
		if result := SetInt64FromInterface(v); !result.IsNull() {
			data.LatestVersion = result
		}
	}
}

// KeyPath returns the Vault API path for reading the key's metadata.
func (m *KeyRotateResourceModel) KeyPath() string {
	return BuildKeyPath(m.Mount.ValueString(), m.Name.ValueString())
}

// getVaultClient returns a Vault client for the given namespace, adding a diagnostic on error.
func (r *KeyRotateResource) getVaultClient(ctx context.Context, namespace string, diags *diag.Diagnostics) (*vaultapi.Client, bool) {
	cli, err := client.GetClient(ctx, r.Meta(), namespace)
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return nil, false
	}
	return cli, true
}

// readKey reads the key metadata from Vault. Returns (data, true) if found, (nil, false) otherwise. API errors are added to diags.
func (r *KeyRotateResource) readKey(ctx context.Context, cli *vaultapi.Client, keyPath string, diags *diag.Diagnostics) (map[string]interface{}, bool) {
	vaultResp, err := cli.Logical().ReadWithContext(ctx, keyPath)
	if err != nil {
		diags.AddError(ErrReading(ResourceTypeKey, keyPath, err))
		return nil, false
	}
	if vaultResp == nil {
		return nil, false
	}
	return vaultResp.Data, true
}
