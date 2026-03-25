// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package os

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
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
	"github.com/hashicorp/terraform-provider-vault/util"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &OSSecretBackendHostResource{}

// NewOSSecretBackendHostResource returns the implementation for this resource
func NewOSSecretBackendHostResource() resource.Resource {
	return &OSSecretBackendHostResource{}
}

// OSSecretBackendHostResource implements the methods that define this resource
type OSSecretBackendHostResource struct {
	base.ResourceWithConfigure
}

// OSSecretBackendHostModel describes the Terraform resource data model
type OSSecretBackendHostModel struct {
	base.BaseModelLegacy

	Mount                    types.String `tfsdk:"mount"`
	Name                     types.String `tfsdk:"name"`
	Type                     types.String `tfsdk:"type"`
	Address                  types.String `tfsdk:"address"`
	Port                     types.Int64  `tfsdk:"port"`
	SSHHostKey               types.String `tfsdk:"ssh_host_key"`
	PasswordPolicy           types.String `tfsdk:"password_policy"`
	RotationPeriod           types.String `tfsdk:"rotation_period"`
	RotationSchedule         types.String `tfsdk:"rotation_schedule"`
	RotationWindow           types.String `tfsdk:"rotation_window"`
	DisableAutomatedRotation types.Bool   `tfsdk:"disable_automated_rotation"`
	CustomMetadata           types.Map    `tfsdk:"custom_metadata"`
}

// OSSecretBackendHostAPIModel describes the Vault API data model
type OSSecretBackendHostAPIModel struct {
	Type                     string            `json:"type" mapstructure:"type"`
	Address                  string            `json:"address" mapstructure:"address"`
	Port                     int64             `json:"port,omitempty" mapstructure:"port"`
	SSHHostKey               string            `json:"ssh_host_key,omitempty" mapstructure:"ssh_host_key"`
	PasswordPolicy           string            `json:"password_policy,omitempty" mapstructure:"password_policy"`
	RotationPeriod           string            `json:"rotation_period,omitempty" mapstructure:"rotation_period"`
	RotationSchedule         string            `json:"rotation_schedule,omitempty" mapstructure:"rotation_schedule"`
	RotationWindow           string            `json:"rotation_window,omitempty" mapstructure:"rotation_window"`
	DisableAutomatedRotation bool              `json:"disable_automated_rotation,omitempty" mapstructure:"disable_automated_rotation"`
	CustomMetadata           map[string]string `json:"custom_metadata,omitempty" mapstructure:"custom_metadata"`
}

func (r *OSSecretBackendHostResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_os_secret_backend_host"
}

func (r *OSSecretBackendHostResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path where the OS secrets backend is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the host.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldType: schema.StringAttribute{
				MarkdownDescription: "Type of the host OS (e.g., 'rhel', 'ubuntu', 'windows').",
				Required:            true,
			},
			consts.FieldAddress: schema.StringAttribute{
				MarkdownDescription: "Address of the host (hostname or IP).",
				Required:            true,
			},
			consts.FieldPort: schema.Int64Attribute{
				MarkdownDescription: "Port to connect to on the host.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(22),
			},
			consts.FieldSSHHostKey: schema.StringAttribute{
				MarkdownDescription: "SSH host key for the host.",
				Optional:            true,
			},
			consts.FieldPasswordPolicy: schema.StringAttribute{
				MarkdownDescription: "Name of the password policy to use for password generation.",
				Optional:            true,
			},
			consts.FieldRotationPeriod: schema.StringAttribute{
				MarkdownDescription: "How often to rotate passwords (e.g., '24h'). Mutually exclusive with rotation_schedule.",
				Optional:            true,
			},
			consts.FieldRotationSchedule: schema.StringAttribute{
				MarkdownDescription: "Cron schedule for password rotation. Mutually exclusive with rotation_period.",
				Optional:            true,
			},
			consts.FieldRotationWindow: schema.StringAttribute{
				MarkdownDescription: "Window of time for password rotation.",
				Optional:            true,
			},
			consts.FieldDisableAutomatedRotation: schema.BoolAttribute{
				MarkdownDescription: "Disable automated password rotation.",
				Optional:            true,
			},
			consts.FieldCustomMetadata: schema.MapAttribute{
				MarkdownDescription: "Custom metadata for the host.",
				ElementType:         types.StringType,
				Optional:            true,
			},
		},
		MarkdownDescription: "Manages a host in an OS Secrets Engine mount in Vault.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

// readHostFromVault reads the host configuration from Vault and populates the model
func (r *OSSecretBackendHostResource) readHostFromVault(ctx context.Context, cli *api.Client, data *OSSecretBackendHostModel, diags *diag.Diagnostics) {
	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/hosts/%s", mount, name)

	readResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		diags.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiModel OSSecretBackendHostAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values back to Terraform model
	data.Type = types.StringValue(apiModel.Type)
	data.Address = types.StringValue(apiModel.Address)
	if apiModel.Port != 0 {
		data.Port = types.Int64Value(apiModel.Port)
	}
	if apiModel.SSHHostKey != "" {
		data.SSHHostKey = types.StringValue(apiModel.SSHHostKey)
	}
	if apiModel.PasswordPolicy != "" {
		data.PasswordPolicy = types.StringValue(apiModel.PasswordPolicy)
	}
	if apiModel.RotationPeriod != "" {
		data.RotationPeriod = types.StringValue(apiModel.RotationPeriod)
	}
	if apiModel.RotationSchedule != "" {
		data.RotationSchedule = types.StringValue(apiModel.RotationSchedule)
	}
	if apiModel.RotationWindow != "" {
		data.RotationWindow = types.StringValue(apiModel.RotationWindow)
	}
	data.DisableAutomatedRotation = types.BoolValue(apiModel.DisableAutomatedRotation)

	// Set custom_metadata if it has values or was set in config
	if len(apiModel.CustomMetadata) > 0 || !data.CustomMetadata.IsNull() {
		customMetadataVal, customMetadataDiags := types.MapValueFrom(ctx, types.StringType, apiModel.CustomMetadata)
		diags.Append(customMetadataDiags...)
		if !diags.HasError() {
			data.CustomMetadata = customMetadataVal
		}
	}
}

func (r *OSSecretBackendHostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data OSSecretBackendHostModel
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

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/hosts/%s", mount, name)

	// Build the request data
	requestData := make(map[string]interface{})
	requestData[consts.FieldType] = data.Type.ValueString()
	requestData[consts.FieldAddress] = data.Address.ValueString()

	if !data.Port.IsNull() && !data.Port.IsUnknown() {
		requestData[consts.FieldPort] = data.Port.ValueInt64()
	}
	if !data.SSHHostKey.IsNull() && !data.SSHHostKey.IsUnknown() {
		requestData[consts.FieldSSHHostKey] = data.SSHHostKey.ValueString()
	}
	if !data.PasswordPolicy.IsNull() && !data.PasswordPolicy.IsUnknown() {
		requestData[consts.FieldPasswordPolicy] = data.PasswordPolicy.ValueString()
	}
	if !data.RotationPeriod.IsNull() && !data.RotationPeriod.IsUnknown() {
		requestData[consts.FieldRotationPeriod] = data.RotationPeriod.ValueString()
	}
	if !data.RotationSchedule.IsNull() && !data.RotationSchedule.IsUnknown() {
		requestData[consts.FieldRotationSchedule] = data.RotationSchedule.ValueString()
	}
	if !data.RotationWindow.IsNull() && !data.RotationWindow.IsUnknown() {
		requestData[consts.FieldRotationWindow] = data.RotationWindow.ValueString()
	}
	if !data.DisableAutomatedRotation.IsNull() && !data.DisableAutomatedRotation.IsUnknown() {
		requestData[consts.FieldDisableAutomatedRotation] = data.DisableAutomatedRotation.ValueBool()
	}
	if !data.CustomMetadata.IsNull() && !data.CustomMetadata.IsUnknown() {
		var customMetadata map[string]string
		if diags := data.CustomMetadata.ElementsAs(ctx, &customMetadata, false); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		requestData[consts.FieldCustomMetadata] = customMetadata
	}

	_, err = cli.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error writing OS secret backend host to %q", path),
			err.Error(),
		)
		return
	}

	// Set the ID
	data.ID = types.StringValue(makeHostID(mount, name))

	// Read back the configuration
	r.readHostFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendHostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data OSSecretBackendHostModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.readHostFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendHostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data OSSecretBackendHostModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/hosts/%s", mount, name)

	// Build the request data
	requestData := make(map[string]interface{})
	requestData[consts.FieldType] = data.Type.ValueString()
	requestData[consts.FieldAddress] = data.Address.ValueString()

	if !data.Port.IsNull() && !data.Port.IsUnknown() {
		requestData[consts.FieldPort] = data.Port.ValueInt64()
	}
	if !data.SSHHostKey.IsNull() && !data.SSHHostKey.IsUnknown() {
		requestData[consts.FieldSSHHostKey] = data.SSHHostKey.ValueString()
	}
	if !data.PasswordPolicy.IsNull() && !data.PasswordPolicy.IsUnknown() {
		requestData[consts.FieldPasswordPolicy] = data.PasswordPolicy.ValueString()
	}
	if !data.RotationPeriod.IsNull() && !data.RotationPeriod.IsUnknown() {
		requestData[consts.FieldRotationPeriod] = data.RotationPeriod.ValueString()
	}
	if !data.RotationSchedule.IsNull() && !data.RotationSchedule.IsUnknown() {
		requestData[consts.FieldRotationSchedule] = data.RotationSchedule.ValueString()
	}
	if !data.RotationWindow.IsNull() && !data.RotationWindow.IsUnknown() {
		requestData[consts.FieldRotationWindow] = data.RotationWindow.ValueString()
	}
	if !data.DisableAutomatedRotation.IsNull() && !data.DisableAutomatedRotation.IsUnknown() {
		requestData[consts.FieldDisableAutomatedRotation] = data.DisableAutomatedRotation.ValueBool()
	}
	if !data.CustomMetadata.IsNull() && !data.CustomMetadata.IsUnknown() {
		var customMetadata map[string]string
		if diags := data.CustomMetadata.ElementsAs(ctx, &customMetadata, false); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		requestData[consts.FieldCustomMetadata] = customMetadata
	}

	_, err = cli.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error updating OS secret backend host at %q", path),
			err.Error(),
		)
		return
	}

	// Read back the configuration
	r.readHostFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendHostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data OSSecretBackendHostModel
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
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/hosts/%s", mount, name)

	_, err = cli.Logical().DeleteWithContext(ctx, path)
	if err != nil && !util.Is404(err) {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error deleting OS secret backend host at %q", path),
			err.Error(),
		)
	}
}

func (r *OSSecretBackendHostResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Parse the ID: {mount}/hosts/{name}
	mount, name, err := parseHostID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}

	var data OSSecretBackendHostModel
	data.ID = types.StringValue(makeHostID(mount, name))
	data.Mount = types.StringValue(mount)
	data.Name = types.StringValue(name)

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.readHostFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Made with Bob
