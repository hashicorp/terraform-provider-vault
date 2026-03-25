// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package os

import (
	"context"
	"fmt"

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
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &OSSecretBackendAccountResource{}

// NewOSSecretBackendAccountResource returns the implementation for this resource
func NewOSSecretBackendAccountResource() resource.Resource {
	return &OSSecretBackendAccountResource{}
}

// OSSecretBackendAccountResource implements the methods that define this resource
type OSSecretBackendAccountResource struct {
	base.ResourceWithConfigure
}

// OSSecretBackendAccountModel describes the Terraform resource data model
type OSSecretBackendAccountModel struct {
	base.BaseModelLegacy

	Mount                    types.String `tfsdk:"mount"`
	Host                     types.String `tfsdk:"host"`
	Name                     types.String `tfsdk:"name"`
	Username                 types.String `tfsdk:"username"`
	Password                 types.String `tfsdk:"password"`
	ParentAccountRef         types.String `tfsdk:"parent_account_ref"`
	PasswordPolicy           types.String `tfsdk:"password_policy"`
	RotationPeriod           types.String `tfsdk:"rotation_period"`
	RotationSchedule         types.String `tfsdk:"rotation_schedule"`
	RotationWindow           types.String `tfsdk:"rotation_window"`
	DisableAutomatedRotation types.Bool   `tfsdk:"disable_automated_rotation"`
	VerifyConnection         types.Bool   `tfsdk:"verify_connection"`
	CustomMetadata           types.Map    `tfsdk:"custom_metadata"`
	LastVaultRotation        types.String `tfsdk:"last_vault_rotation"`
	NextVaultRotation        types.String `tfsdk:"next_vault_rotation"`
}

// OSSecretBackendAccountAPIModel describes the Vault API data model
type OSSecretBackendAccountAPIModel struct {
	Username                 string            `json:"username" mapstructure:"username"`
	Password                 string            `json:"password,omitempty" mapstructure:"password"`
	ParentAccountRef         string            `json:"parent_account_ref,omitempty" mapstructure:"parent_account_ref"`
	PasswordPolicy           string            `json:"password_policy,omitempty" mapstructure:"password_policy"`
	RotationPeriod           string            `json:"rotation_period,omitempty" mapstructure:"rotation_period"`
	RotationSchedule         string            `json:"rotation_schedule,omitempty" mapstructure:"rotation_schedule"`
	RotationWindow           string            `json:"rotation_window,omitempty" mapstructure:"rotation_window"`
	DisableAutomatedRotation bool              `json:"disable_automated_rotation,omitempty" mapstructure:"disable_automated_rotation"`
	VerifyConnection         bool              `json:"verify_connection,omitempty" mapstructure:"verify_connection"`
	CustomMetadata           map[string]string `json:"custom_metadata,omitempty" mapstructure:"custom_metadata"`
	LastVaultRotation        string            `json:"last_vault_rotation,omitempty" mapstructure:"last_vault_rotation"`
	NextVaultRotation        string            `json:"next_vault_rotation,omitempty" mapstructure:"next_vault_rotation"`
}

func (r *OSSecretBackendAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_os_secret_backend_account"
}

func (r *OSSecretBackendAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path where the OS secrets backend is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldHost: schema.StringAttribute{
				MarkdownDescription: "Name of the host this account belongs to.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the account.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldUsername: schema.StringAttribute{
				MarkdownDescription: "Username for the account.",
				Required:            true,
			},
			consts.FieldPassword: schema.StringAttribute{
				MarkdownDescription: "Password for the account. This is write-only and will not be read back from Vault.",
				Required:            true,
				Sensitive:           true,
				WriteOnly:           true,
			},
			consts.FieldParentAccountRef: schema.StringAttribute{
				MarkdownDescription: "Reference to a parent account for rotation management.",
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
			consts.FieldVerifyConnection: schema.BoolAttribute{
				MarkdownDescription: "Verify the connection to the host with the provided credentials.",
				Optional:            true,
			},
			consts.FieldCustomMetadata: schema.MapAttribute{
				MarkdownDescription: "Custom metadata for the account.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			consts.FieldLastVaultRotation: schema.StringAttribute{
				MarkdownDescription: "Timestamp of the last password rotation by Vault.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldNextVaultRotation: schema.StringAttribute{
				MarkdownDescription: "Timestamp of the next scheduled password rotation by Vault.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
		MarkdownDescription: "Manages an account on a host in an OS Secrets Engine mount in Vault.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

// readAccountFromVault reads the account configuration from Vault and populates the model
// Note: Password is write-only and will not be read back
func (r *OSSecretBackendAccountResource) readAccountFromVault(ctx context.Context, cli *api.Client, data *OSSecretBackendAccountModel, diags *diag.Diagnostics) {
	mount := data.Mount.ValueString()
	host := data.Host.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/hosts/%s/accounts/%s", mount, host, name)

	readResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		diags.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiModel OSSecretBackendAccountAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values back to Terraform model
	data.Username = types.StringValue(apiModel.Username)
	// Note: Password is write-only, do not read it back from Vault

	if apiModel.ParentAccountRef != "" {
		data.ParentAccountRef = types.StringValue(apiModel.ParentAccountRef)
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
	data.VerifyConnection = types.BoolValue(apiModel.VerifyConnection)

	// Set computed fields
	if apiModel.LastVaultRotation != "" {
		data.LastVaultRotation = types.StringValue(apiModel.LastVaultRotation)
	}
	if apiModel.NextVaultRotation != "" {
		data.NextVaultRotation = types.StringValue(apiModel.NextVaultRotation)
	}

	// Set custom_metadata if it has values or was set in config
	if len(apiModel.CustomMetadata) > 0 || !data.CustomMetadata.IsNull() {
		customMetadataVal, customMetadataDiags := types.MapValueFrom(ctx, types.StringType, apiModel.CustomMetadata)
		diags.Append(customMetadataDiags...)
		if !diags.HasError() {
			data.CustomMetadata = customMetadataVal
		}
	}
}

func (r *OSSecretBackendAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data OSSecretBackendAccountModel
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
	host := data.Host.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/hosts/%s/accounts/%s", mount, host, name)

	// Build the request data
	requestData := make(map[string]interface{})
	requestData[consts.FieldUsername] = data.Username.ValueString()
	requestData[consts.FieldPassword] = data.Password.ValueString()

	if !data.ParentAccountRef.IsNull() && !data.ParentAccountRef.IsUnknown() {
		requestData[consts.FieldParentAccountRef] = data.ParentAccountRef.ValueString()
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
	if !data.VerifyConnection.IsNull() && !data.VerifyConnection.IsUnknown() {
		requestData[consts.FieldVerifyConnection] = data.VerifyConnection.ValueBool()
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
			fmt.Sprintf("Error writing OS secret backend account to %q", path),
			err.Error(),
		)
		return
	}

	// Set the ID
	data.ID = types.StringValue(makeAccountID(mount, host, name))

	// Read back the configuration (password will not be read back)
	r.readAccountFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data OSSecretBackendAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.readAccountFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data OSSecretBackendAccountModel
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
	host := data.Host.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/hosts/%s/accounts/%s", mount, host, name)

	// Build the request data
	requestData := make(map[string]interface{})
	requestData[consts.FieldUsername] = data.Username.ValueString()
	requestData[consts.FieldPassword] = data.Password.ValueString()

	if !data.ParentAccountRef.IsNull() && !data.ParentAccountRef.IsUnknown() {
		requestData[consts.FieldParentAccountRef] = data.ParentAccountRef.ValueString()
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
	if !data.VerifyConnection.IsNull() && !data.VerifyConnection.IsUnknown() {
		requestData[consts.FieldVerifyConnection] = data.VerifyConnection.ValueBool()
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
			fmt.Sprintf("Error updating OS secret backend account at %q", path),
			err.Error(),
		)
		return
	}

	// Read back the configuration (password will not be read back)
	r.readAccountFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data OSSecretBackendAccountModel
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
	host := data.Host.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/hosts/%s/accounts/%s", mount, host, name)

	_, err = cli.Logical().DeleteWithContext(ctx, path)
	if err != nil && !util.Is404(err) {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error deleting OS secret backend account at %q", path),
			err.Error(),
		)
	}
}

func (r *OSSecretBackendAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Parse the ID: {mount}/hosts/{host}/accounts/{name}
	mount, host, name, err := parseAccountID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}

	var data OSSecretBackendAccountModel
	data.ID = types.StringValue(makeAccountID(mount, host, name))
	data.Mount = types.StringValue(mount)
	data.Host = types.StringValue(host)
	data.Name = types.StringValue(name)

	// Password must be set after import since it's write-only
	// Set it to a placeholder that will force user to update
	data.Password = types.StringValue("IMPORT_PLACEHOLDER_UPDATE_REQUIRED")

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.readAccountFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Made with Bob
