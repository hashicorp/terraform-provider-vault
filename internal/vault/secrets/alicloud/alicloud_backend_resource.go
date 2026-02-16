// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/path"
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

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &AliCloudSecretBackendResource{}

// NewAliCloudSecretBackendResource returns the implementation for this resource
func NewAliCloudSecretBackendResource() resource.Resource {
	return &AliCloudSecretBackendResource{}
}

// AliCloudSecretBackendResource implements the methods that define this resource
type AliCloudSecretBackendResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// AliCloudSecretBackendModel describes the Terraform resource data model
type AliCloudSecretBackendModel struct {
	base.BaseModelLegacy

	Path               types.String `tfsdk:"path"`
	AccessKey          types.String `tfsdk:"access_key"`
	SecretKeyWO        types.String `tfsdk:"secret_key_wo"`
	SecretKeyWOVersion types.Int64  `tfsdk:"secret_key_wo_version"`
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
			consts.FieldSecretKeyWOVersion: schema.Int64Attribute{
				MarkdownDescription: "Version number for the write-only secret key. Increment this value to force credential rotation.",
				Required:            true,
			},
		},
		MarkdownDescription: "Manages an AliCloud secrets engine backend in Vault.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

func (r *AliCloudSecretBackendResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AliCloudSecretBackendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
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
	log.Printf("[DEBUG] Mounting AliCloud secrets engine at %q", mountPath)

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

	// Build config data - always use secret_key_wo
	configData := map[string]interface{}{
		consts.FieldAccessKey: data.AccessKey.ValueString(),
		consts.FieldSecretKey: data.SecretKeyWO.ValueString(),
	}

	log.Printf("[DEBUG] Configuring AliCloud backend at %q", configPath)
	if _, err := cli.Logical().WriteWithContext(ctx, configPath, configData); err != nil {
		resp.Diagnostics.AddError(
			"Error configuring AliCloud backend",
			fmt.Sprintf("Error configuring AliCloud backend at path %q: %s", configPath, err),
		)
		return
	}

	// Read back the state from Vault to ensure all computed values are set
	// Note: ID will be set in the Read function
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
	configPath := fmt.Sprintf("%s/config", mountPath)

	log.Printf("[DEBUG] Reading AliCloud backend config from %q", configPath)
	secret, err := cli.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading AliCloud backend config",
			fmt.Sprintf("Error reading AliCloud backend config from path %q: %s", configPath, err),
		)
		return
	}

	if secret == nil {
		log.Printf("[WARN] AliCloud backend config not found at %q, removing from state", configPath)
		resp.State.RemoveResource(ctx)
		return
	}

	// Update access_key if returned by Vault (it's computed and sensitive)
	if accessKey, ok := secret.Data[consts.FieldAccessKey].(string); ok {
		data.AccessKey = types.StringValue(accessKey)
	}

	// Set ID to the mount path
	data.ID = types.StringValue(mountPath)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AliCloudSecretBackendResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state AliCloudSecretBackendModel
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

	mountPath := plan.Path.ValueString()
	configPath := fmt.Sprintf("%s/config", mountPath)

	// Build config data - Vault API requires both access_key and secret_key
	configData := map[string]interface{}{
		consts.FieldAccessKey: plan.AccessKey.ValueString(),
		consts.FieldSecretKey: plan.SecretKeyWO.ValueString(),
	}

	log.Printf("[DEBUG] Updating AliCloud backend config at %q", configPath)

	if _, err := cli.Logical().WriteWithContext(ctx, configPath, configData); err != nil {
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
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
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
	log.Printf("[DEBUG] Unmounting AliCloud backend at %q", mountPath)

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
}
