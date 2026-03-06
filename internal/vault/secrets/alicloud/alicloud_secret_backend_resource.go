// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &AliCloudSecretBackendResource{}

// NewAliCloudSecretBackendResource returns the implementation for this resource
func NewAliCloudSecretBackendResource() resource.Resource {
	return &AliCloudSecretBackendResource{}
}

// AliCloudSecretBackendResource implements the methods that define this resource
type AliCloudSecretBackendResource struct {
	base.ResourceWithConfigure
}

// AliCloudSecretBackendModel describes the Terraform resource data model
type AliCloudSecretBackendModel struct {
	base.BaseModel

	Path        types.String `tfsdk:"path"`
	AccessKey   types.String `tfsdk:"access_key"`
	SecretKeyWO types.String `tfsdk:"secret_key_wo"`
	Accessor    types.String `tfsdk:"accessor"`
}

func (r *AliCloudSecretBackendResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_alicloud_secret_backend"
}

func (r *AliCloudSecretBackendResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				MarkdownDescription: "Path where the AliCloud secrets engine will be mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldAccessKey: schema.StringAttribute{
				MarkdownDescription: "The AliCloud Access Key ID to use when generating new credentials.",
				Required:            true,
				Sensitive:           true,
			},
			consts.FieldSecretKeyWO: schema.StringAttribute{
				MarkdownDescription: "Write-only AliCloud Secret Access Key. This value will never be read back from Vault.",
				Required:            true,
				Sensitive:           true,
				WriteOnly:           true,
			},
			consts.FieldAccessor: schema.StringAttribute{
				MarkdownDescription: "Accessor of the mount.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Manages an AliCloud secrets engine backend in Vault.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *AliCloudSecretBackendResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AliCloudSecretBackendModel
	// Read from Plan for non-write-only attributes
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read write-only attribute from Config (not Plan)
	// Write-only attributes are nullified in Plan, so we must read from Config
	var configData AliCloudSecretBackendModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &configData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Mount the backend
	mountPath := data.Path.ValueString()
	tflog.Debug(ctx, "Mounting AliCloud secrets engine", map[string]any{
		"path": mountPath,
	})

	mountConfig := &api.MountInput{
		Type: consts.MountTypeAliCloud,
	}

	if err := cli.Sys().MountWithContext(ctx, mountPath, mountConfig); err != nil {
		resp.Diagnostics.AddError(
			"Error mounting AliCloud backend",
			fmt.Sprintf("Error mounting AliCloud backend at path %q: %s", mountPath, err),
		)
		return
	}

	// Configure the backend
	configPath := fmt.Sprintf("%s/config", mountPath)

	// Build config data - use secret_key_wo from Config (write-only attributes are nullified in Plan)
	secretKeyValue := configData.SecretKeyWO.ValueString()
	tflog.Debug(ctx, "AliCloud secret_key_wo details", map[string]any{
		"is_null":    configData.SecretKeyWO.IsNull(),
		"is_unknown": configData.SecretKeyWO.IsUnknown(),
		"value_len":  len(secretKeyValue),
	})

	vaultConfigData := map[string]interface{}{
		consts.FieldAccessKey: data.AccessKey.ValueString(),
		consts.FieldSecretKey: secretKeyValue,
	}

	tflog.Debug(ctx, "Configuring AliCloud backend", map[string]any{
		"config_path":    configPath,
		"access_key_len": len(data.AccessKey.ValueString()),
	})
	if _, err := cli.Logical().WriteWithContext(ctx, configPath, vaultConfigData); err != nil {
		resp.Diagnostics.AddError(
			"Error configuring AliCloud backend",
			fmt.Sprintf("Error configuring AliCloud backend at path %q: %s", configPath, err),
		)
		return
	}

	// Read back the state from Vault to ensure all computed values are set
	readReq := resource.ReadRequest{State: resp.State}
	readResp := resource.ReadResponse{State: resp.State}

	// Set the state so Read can use it
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readReq.State = resp.State
	r.Read(ctx, readReq, &readResp)
	resp.Diagnostics.Append(readResp.Diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.State = readResp.State
}

func (r *AliCloudSecretBackendResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AliCloudSecretBackendModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := data.Path.ValueString()

	// Read mount information to get accessor
	tflog.Debug(ctx, "Reading mount information", map[string]any{
		"path": mountPath,
	})
	mounts, err := cli.Sys().ListMountsWithContext(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading mount information",
			fmt.Sprintf("Error reading mount information for path %q: %s", mountPath, err),
		)
		return
	}

	// Find the mount and get its accessor
	// Vault returns mounts with trailing slash
	mountKey := mountPath + "/"
	if mount, ok := mounts[mountKey]; ok {
		data.Accessor = types.StringValue(mount.Accessor)
		tflog.Debug(ctx, "Found accessor for mount", map[string]any{
			"accessor": mount.Accessor,
			"path":     mountPath,
		})
	} else {
		tflog.Warn(ctx, "Mount not found in mount list", map[string]any{
			"path": mountPath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	configPath := fmt.Sprintf("%s/config", mountPath)

	tflog.Debug(ctx, "Reading AliCloud backend config", map[string]any{
		"config_path": configPath,
	})
	secret, err := cli.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading AliCloud backend config",
			fmt.Sprintf("Error reading AliCloud backend config from path %q: %s", configPath, err),
		)
		return
	}

	if secret == nil {
		tflog.Warn(ctx, "AliCloud backend config not found, removing from state", map[string]any{
			"config_path": configPath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// Update access_key if returned by Vault (it's computed and sensitive)
	if accessKey, ok := secret.Data[consts.FieldAccessKey].(string); ok {
		data.AccessKey = types.StringValue(accessKey)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AliCloudSecretBackendResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AliCloudSecretBackendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read write-only attribute from Config (not Plan)
	var configData AliCloudSecretBackendModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &configData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := data.Path.ValueString()
	configPath := fmt.Sprintf("%s/config", mountPath)

	// Build config data - Vault API requires both access_key and secret_key
	// Use secret_key_wo from Config (write-only attributes are nullified in Plan)
	vaultConfigData := map[string]interface{}{
		consts.FieldAccessKey: data.AccessKey.ValueString(),
		consts.FieldSecretKey: configData.SecretKeyWO.ValueString(),
	}

	tflog.Debug(ctx, "Updating AliCloud backend config", map[string]any{
		"config_path": configPath,
	})

	if _, err := cli.Logical().WriteWithContext(ctx, configPath, vaultConfigData); err != nil {
		resp.Diagnostics.AddError(
			"Error updating AliCloud backend config",
			fmt.Sprintf("Error updating AliCloud backend config at path %q: %s", configPath, err),
		)
		return
	}

	// Read back from Vault to ensure all computed values are set
	readReq := resource.ReadRequest{State: resp.State}
	readResp := resource.ReadResponse{State: resp.State}

	// Set plan to state first so Read can use it
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readReq.State = resp.State
	r.Read(ctx, readReq, &readResp)
	resp.Diagnostics.Append(readResp.Diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.State = readResp.State
}

func (r *AliCloudSecretBackendResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AliCloudSecretBackendModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := data.Path.ValueString()
	tflog.Debug(ctx, "Unmounting AliCloud backend", map[string]any{
		"path": mountPath,
	})

	if err := cli.Sys().UnmountWithContext(ctx, mountPath); err != nil {
		resp.Diagnostics.AddError(
			"Error unmounting AliCloud backend",
			fmt.Sprintf("Error unmounting AliCloud backend at path %q: %s", mountPath, err),
		)
		return
	}
}

func (r *AliCloudSecretBackendResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldPath), req, resp)

	// Set namespace from environment variable if provided
	// This supports importing resources that exist inside a Vault namespace
	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import with namespace", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}
