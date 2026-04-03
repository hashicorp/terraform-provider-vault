// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package os

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
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
}

// OSSecretBackendModel describes the Terraform resource data model
type OSSecretBackendModel struct {
	base.BaseModel

	Mount types.String `tfsdk:"mount"`

	MaxVersions               types.Int64 `tfsdk:"max_versions"`
	SSHHostKeyTrustOnFirstUse types.Bool  `tfsdk:"ssh_host_key_trust_on_first_use"`
}

// OSSecretBackendAPIModel describes the Vault API data model
type OSSecretBackendAPIModel struct {
	MaxVersions               int64 `json:"max_versions,omitempty" mapstructure:"max_versions"`
	SSHHostKeyTrustOnFirstUse bool  `json:"ssh_host_key_trust_on_first_use,omitempty" mapstructure:"ssh_host_key_trust_on_first_use"`
}

func (m OSSecretBackendModel) configPath() string {
	return fmt.Sprintf("%s/config", m.Mount.ValueString())
}

func (r *OSSecretBackendResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_os_secret_backend"
}

func (r *OSSecretBackendResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path where the OS secrets backend is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldMaxVersions: schema.Int64Attribute{
				MarkdownDescription: "Maximum number of versions to keep for secrets.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldSSHHostKeyTrustOnFirstUse: schema.BoolAttribute{
				MarkdownDescription: "Trust SSH host keys on first use.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
		},
		MarkdownDescription: "Manages the configuration of an existing OS Secrets Engine mount in Vault.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *OSSecretBackendResource) readBackendFromVault(ctx context.Context, cli *api.Client, data *OSSecretBackendModel, diags *diag.Diagnostics) bool {
	readResp, err := cli.Logical().ReadWithContext(ctx, data.configPath())
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return false
	}
	if readResp == nil {
		return false
	}

	var apiModel OSSecretBackendAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return false
	}

	data.MaxVersions = types.Int64Value(apiModel.MaxVersions)
	data.SSHHostKeyTrustOnFirstUse = types.BoolValue(apiModel.SSHHostKeyTrustOnFirstUse)

	return true
}

func (r *OSSecretBackendResource) buildRequestData(data *OSSecretBackendModel, configuredMaxVersions types.Int64, stateData *OSSecretBackendModel) map[string]interface{} {
	requestData := make(map[string]interface{})

	if !configuredMaxVersions.IsNull() && !configuredMaxVersions.IsUnknown() {
		requestData[consts.FieldMaxVersions] = configuredMaxVersions.ValueInt64()
	} else if stateData != nil && !stateData.MaxVersions.IsNull() && !stateData.MaxVersions.IsUnknown() {
		requestData[consts.FieldMaxVersions] = stateData.MaxVersions.ValueInt64()
	}

	requestData[consts.FieldSSHHostKeyTrustOnFirstUse] = data.SSHHostKeyTrustOnFirstUse.ValueBool()

	return requestData
}

func (r *OSSecretBackendResource) writeBackendToVault(ctx context.Context, cli *api.Client, configPath string, requestData map[string]interface{}, operation string, diags *diag.Diagnostics) bool {
	_, err := cli.Logical().WriteWithContext(ctx, configPath, requestData)
	if err != nil {
		diags.AddError(
			fmt.Sprintf("Error %s OS secret backend config at %q", operation, configPath),
			err.Error(),
		)
		return false
	}

	return true
}

func (r *OSSecretBackendResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data OSSecretBackendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var configuredMaxVersions types.Int64
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldMaxVersions), &configuredMaxVersions)...)
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

	mount := data.Mount.ValueString()
	if !ensureOSMountExists(ctx, cli, mount, &resp.Diagnostics) {
		return
	}

	configPath := data.configPath()
	requestData := r.buildRequestData(&data, configuredMaxVersions, nil)

	if !r.writeBackendToVault(ctx, cli, configPath, requestData, "writing", &resp.Diagnostics) {
		return
	}

	if !r.readBackendFromVault(ctx, cli, &data, &resp.Diagnostics) {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

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

	mount := data.Mount.ValueString()

	if !checkOSMountExists(ctx, cli, mount, &resp.Diagnostics) {
		if !resp.Diagnostics.HasError() {
			resp.State.RemoveResource(ctx)
		}
		return
	}

	if !r.readBackendFromVault(ctx, cli, &data, &resp.Diagnostics) {
		// Resource was deleted outside Terraform - remove from state
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var stateData OSSecretBackendModel
	resp.Diagnostics.Append(req.State.Get(ctx, &stateData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var data OSSecretBackendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var configuredMaxVersions types.Int64
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldMaxVersions), &configuredMaxVersions)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	if !ensureOSMountExists(ctx, cli, mount, &resp.Diagnostics) {
		return
	}

	configPath := data.configPath()
	requestData := r.buildRequestData(&data, configuredMaxVersions, &stateData)

	if !r.writeBackendToVault(ctx, cli, configPath, requestData, "updating", &resp.Diagnostics) {
		return
	}

	if !r.readBackendFromVault(ctx, cli, &data, &resp.Diagnostics) {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

func (r *OSSecretBackendResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount := req.ID

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

func ensureOSMountExists(ctx context.Context, cli *api.Client, path string, diags *diag.Diagnostics) bool {
	_, err := mountutil.GetMount(ctx, cli, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			diags.AddError(
				"OS secret backend mount not found",
				fmt.Sprintf("No OS secret backend mount exists at %q. Create it first with vault_mount.", path),
			)
			return false
		}

		diags.AddError(errutil.VaultReadErr(err))
		return false
	}

	return true
}

func checkOSMountExists(ctx context.Context, cli *api.Client, path string, diags *diag.Diagnostics) bool {
	_, err := mountutil.GetMount(ctx, cli, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			return false
		}

		diags.AddError(errutil.VaultReadErr(err))
		return false
	}

	return true
}
