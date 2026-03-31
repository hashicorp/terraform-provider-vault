// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package os

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &OSSecretBackendResource{}

// NewOSSecretBackendResource returns the implementation for this resource
func NewOSSecretBackendResource() resource.Resource {
	return &OSSecretBackendResource{}
}

// OSSecretBackendResource implements the methods that define this resource
type OSSecretBackendResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// OSSecretBackendModel describes the Terraform resource data model
type OSSecretBackendModel struct {
	base.BaseModel

	Path                      types.String `tfsdk:"path"`
	MaxVersions               types.Int64  `tfsdk:"max_versions"`
	SSHHostKeyTrustOnFirstUse types.Bool   `tfsdk:"ssh_host_key_trust_on_first_use"`
	PasswordPolicy            types.String `tfsdk:"password_policy"`
}

// OSSecretBackendAPIModel describes the Vault API data model
type OSSecretBackendAPIModel struct {
	MaxVersions               int64  `json:"max_versions,omitempty" mapstructure:"max_versions"`
	SSHHostKeyTrustOnFirstUse bool   `json:"ssh_host_key_trust_on_first_use,omitempty" mapstructure:"ssh_host_key_trust_on_first_use"`
	PasswordPolicy            string `json:"password_policy,omitempty" mapstructure:"password_policy"`
}

func (r *OSSecretBackendResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_os_secret_backend"
}

func (r *OSSecretBackendResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				MarkdownDescription: "Path where the OS secrets backend is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldMaxVersions: schema.Int64Attribute{
				MarkdownDescription: "Maximum number of versions to keep for secrets.",
				Optional:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldSSHHostKeyTrustOnFirstUse: schema.BoolAttribute{
				MarkdownDescription: "Trust SSH host keys on first use.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldPasswordPolicy: schema.StringAttribute{
				MarkdownDescription: "Name of the password policy to use for password generation. Note: This is a write-only field; Vault does not return this value on read.",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
		MarkdownDescription: "Manages the configuration of an OS Secrets Engine mount in Vault.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *OSSecretBackendResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data OSSecretBackendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if Vault version supports OS Secrets Engine (requires 2.0.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion200) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			"OS Secrets Engine requires Vault version 2.0.0 or later. "+
				"Current Vault version: "+r.Meta().GetVaultVersion().String(),
		)
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := data.Path.ValueString()

	// First, create the mount if it doesn't exist
	mountInput := &api.MountInput{
		Type: consts.MountTypeOS,
	}

	err = cli.Sys().MountWithContext(ctx, path, mountInput)
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error creating OS secret backend mount at %q", path),
			err.Error(),
		)
		return
	}

	configPath := fmt.Sprintf("%s/config", path)

	// Build the request data
	requestData := make(map[string]interface{})

	// Always send optional fields - use zero/empty values to clear them
	if !data.MaxVersions.IsNull() && !data.MaxVersions.IsUnknown() {
		requestData[consts.FieldMaxVersions] = data.MaxVersions.ValueInt64()
	} else {
		requestData[consts.FieldMaxVersions] = 0
	}

	if !data.SSHHostKeyTrustOnFirstUse.IsNull() && !data.SSHHostKeyTrustOnFirstUse.IsUnknown() {
		requestData[consts.FieldSSHHostKeyTrustOnFirstUse] = data.SSHHostKeyTrustOnFirstUse.ValueBool()
	} else {
		requestData[consts.FieldSSHHostKeyTrustOnFirstUse] = false
	}

	if !data.PasswordPolicy.IsNull() && !data.PasswordPolicy.IsUnknown() {
		requestData[consts.FieldPasswordPolicy] = data.PasswordPolicy.ValueString()
	} else {
		requestData[consts.FieldPasswordPolicy] = ""
	}

	_, err = cli.Logical().WriteWithContext(ctx, configPath, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error writing OS secret backend config to %q", configPath),
			err.Error(),
		)
		return
	}

	// Read back the configuration
	readResp, err := cli.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiModel OSSecretBackendAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values back to Terraform model
	if apiModel.MaxVersions != 0 {
		data.MaxVersions = types.Int64Value(apiModel.MaxVersions)
	} else {
		data.MaxVersions = types.Int64Null()
	}

	data.SSHHostKeyTrustOnFirstUse = types.BoolValue(apiModel.SSHHostKeyTrustOnFirstUse)

	// password_policy is write-only in Vault API - it's not returned on read
	// Preserve the value from plan instead of trying to read it
	// Note: data already contains the plan values from req.Plan.Get()

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data OSSecretBackendModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := data.Path.ValueString()
	configPath := fmt.Sprintf("%s/config", path)

	readResp, err := cli.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		// Resource was deleted outside Terraform - remove from state
		resp.State.RemoveResource(ctx)
		return
	}

	var apiModel OSSecretBackendAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values back to Terraform model
	// Always set fields to match Vault state, use null for empty values
	if apiModel.MaxVersions != 0 {
		data.MaxVersions = types.Int64Value(apiModel.MaxVersions)
	} else {
		data.MaxVersions = types.Int64Null()
	}

	data.SSHHostKeyTrustOnFirstUse = types.BoolValue(apiModel.SSHHostKeyTrustOnFirstUse)

	// password_policy is write-only in Vault API - it's not returned on read
	// Preserve the value from current state instead of trying to read it
	// Note: data already contains the current state values from req.State.Get()

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data OSSecretBackendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := data.Path.ValueString()
	configPath := fmt.Sprintf("%s/config", path)

	// Build the request data
	requestData := make(map[string]interface{})

	// Always send optional fields - use zero/empty values to clear them
	if !data.MaxVersions.IsNull() && !data.MaxVersions.IsUnknown() {
		requestData[consts.FieldMaxVersions] = data.MaxVersions.ValueInt64()
	} else {
		requestData[consts.FieldMaxVersions] = 0
	}

	if !data.SSHHostKeyTrustOnFirstUse.IsNull() && !data.SSHHostKeyTrustOnFirstUse.IsUnknown() {
		requestData[consts.FieldSSHHostKeyTrustOnFirstUse] = data.SSHHostKeyTrustOnFirstUse.ValueBool()
	} else {
		requestData[consts.FieldSSHHostKeyTrustOnFirstUse] = false
	}

	if !data.PasswordPolicy.IsNull() && !data.PasswordPolicy.IsUnknown() {
		requestData[consts.FieldPasswordPolicy] = data.PasswordPolicy.ValueString()
	} else {
		requestData[consts.FieldPasswordPolicy] = ""
	}

	_, err = cli.Logical().WriteWithContext(ctx, configPath, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error updating OS secret backend config at %q", configPath),
			err.Error(),
		)
		return
	}

	// Read back the configuration
	readResp, err := cli.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiModel OSSecretBackendAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values back to Terraform model
	if apiModel.MaxVersions != 0 {
		data.MaxVersions = types.Int64Value(apiModel.MaxVersions)
	} else {
		data.MaxVersions = types.Int64Null()
	}

	data.SSHHostKeyTrustOnFirstUse = types.BoolValue(apiModel.SSHHostKeyTrustOnFirstUse)

	// password_policy is write-only in Vault API - it's not returned on read
	// Preserve the value from plan instead of trying to read it
	// Note: data already contains the plan values from req.Plan.Get()

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data OSSecretBackendModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := data.Path.ValueString()

	// Unmount the OS secrets engine
	err = cli.Sys().UnmountWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error deleting OS secret backend mount at %q", path),
			err.Error(),
		)
		return
	}
}

func (r *OSSecretBackendResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Use the built-in helper to set the path attribute from the import ID
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldPath), req, resp)
}

// Made with Bob
