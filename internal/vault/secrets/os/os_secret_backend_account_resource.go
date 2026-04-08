// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package os

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	frameworkrotation "github.com/hashicorp/terraform-provider-vault/internal/framework/rotation"
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
	base.BaseModel

	Mount             types.String `tfsdk:"mount"`
	Host              types.String `tfsdk:"host"`
	Name              types.String `tfsdk:"name"`
	Username          types.String `tfsdk:"username"`
	PasswordWO        types.String `tfsdk:"password_wo"`
	PasswordWOVersion types.Int64  `tfsdk:"password_wo_version"`
	ParentAccountRef  types.String `tfsdk:"parent_account_ref"`
	PasswordPolicy    types.String `tfsdk:"password_policy"`
	frameworkrotation.AutomatedRotationModel
	VerifyConnection  types.Bool   `tfsdk:"verify_connection"`
	CustomMetadata    types.Map    `tfsdk:"custom_metadata"`
	LastVaultRotation types.String `tfsdk:"last_vault_rotation"`
	NextVaultRotation types.String `tfsdk:"next_vault_rotation"`
}

// OSSecretBackendAccountAPIModel describes the Vault API data model
type OSSecretBackendAccountAPIModel struct {
	Username         string `json:"username" mapstructure:"username"`
	Password         string `json:"password,omitempty" mapstructure:"password"`
	ParentAccountRef string `json:"parent_account_ref,omitempty" mapstructure:"parent_account_ref"`
	PasswordPolicy   string `json:"password_policy,omitempty" mapstructure:"password_policy"`
	frameworkrotation.AutomatedRotationAPIModel
	VerifyConnection  bool              `json:"verify_connection,omitempty" mapstructure:"verify_connection"`
	CustomMetadata    map[string]string `json:"custom_metadata,omitempty" mapstructure:"custom_metadata"`
	LastVaultRotation string            `json:"last_vault_rotation,omitempty" mapstructure:"last_vault_rotation"`
	NextVaultRotation string            `json:"next_vault_rotation,omitempty" mapstructure:"next_vault_rotation"`
}

func (m OSSecretBackendAccountModel) vaultPath() string {
	return fmt.Sprintf("%s/hosts/%s/accounts/%s", m.Mount.ValueString(), m.Host.ValueString(), m.Name.ValueString())
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
			consts.FieldPasswordWO: schema.StringAttribute{
				MarkdownDescription: "Password for the account. This is write-only and will not be read back from Vault.",
				Required:            true,
				Sensitive:           true,
				WriteOnly:           true,
			},
			consts.FieldPasswordWOVersion: schema.Int64Attribute{
				MarkdownDescription: "A version counter for the write-only password_wo field. Incrementing this value will trigger an update to the password.",
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.AlsoRequires(
						path.MatchRoot(consts.FieldPasswordWO),
					),
				},
			},
			consts.FieldParentAccountRef: schema.StringAttribute{
				MarkdownDescription: "Reference to a parent account for rotation management.",
				Optional:            true,
			},
			consts.FieldPasswordPolicy: schema.StringAttribute{
				MarkdownDescription: "Name of the password policy to use for password generation.",
				Optional:            true,
			},
			consts.FieldVerifyConnection: schema.BoolAttribute{
				MarkdownDescription: "Verify the connection to the host with the provided credentials.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
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
				MarkdownDescription: "Timestamp of the next scheduled password rotation by Vault. This value may change when rotation configuration is updated.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Manages an account on a host in an OS Secrets Engine mount in Vault.",
	}
	base.MustAddBaseSchema(&resp.Schema)
	frameworkrotation.MustAddAutomatedRotationSchemas(&resp.Schema)
}

// readAccountFromVault reads the account configuration from Vault and populates the model
// Note: Password is write-only and will not be read back
// Returns true if the resource was found, false if it was not found (404)
func (r *OSSecretBackendAccountResource) readAccountFromVault(ctx context.Context, cli *api.Client, data *OSSecretBackendAccountModel, diags *diag.Diagnostics) bool {
	path := data.vaultPath()
	tflog.Debug(ctx, "Reading OS backend account", map[string]any{
		"path": path,
	})

	readResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return false
	}
	if readResp == nil {
		tflog.Warn(ctx, "OS backend account not found, removing from state", map[string]any{
			"path": path,
		})
		// Resource not found (404)
		return false
	}

	var apiModel OSSecretBackendAccountAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return false
	}

	// Map values back to Terraform model
	data.Username = types.StringValue(apiModel.Username)
	// Note: Password is write-only, do not read it back from Vault

	// Set optional fields to null if empty to prevent drift
	if apiModel.ParentAccountRef != "" {
		data.ParentAccountRef = types.StringValue(apiModel.ParentAccountRef)
	} else {
		data.ParentAccountRef = types.StringNull()
	}
	if apiModel.PasswordPolicy != "" {
		data.PasswordPolicy = types.StringValue(apiModel.PasswordPolicy)
	} else {
		data.PasswordPolicy = types.StringNull()
	}

	// Populate rotation fields from API response, following SDKv2 pattern
	// PopulateAutomatedRotationModelFromAPI will set fields to null if API returns zero/empty values
	rotationModel := frameworkrotation.AutomatedRotationModel{}
	rotationAPIModel := frameworkrotation.AutomatedRotationAPIModel(apiModel.AutomatedRotationAPIModel)
	diags.Append(frameworkrotation.PopulateAutomatedRotationModelFromAPI(&rotationModel, &rotationAPIModel)...)
	if diags.HasError() {
		return false
	}
	data.AutomatedRotationModel = rotationModel
	if apiModel.VerifyConnection || data.VerifyConnection.IsNull() || data.VerifyConnection.IsUnknown() {
		data.VerifyConnection = types.BoolValue(apiModel.VerifyConnection)
	}

	// Set computed fields - use values directly from Vault without normalization
	if apiModel.LastVaultRotation != "" {
		data.LastVaultRotation = types.StringValue(apiModel.LastVaultRotation)
	} else {
		data.LastVaultRotation = types.StringNull()
	}

	if apiModel.NextVaultRotation != "" {
		data.NextVaultRotation = types.StringValue(apiModel.NextVaultRotation)
	} else {
		data.NextVaultRotation = types.StringNull()
	}

	// Set custom_metadata - always set to prevent drift
	if len(apiModel.CustomMetadata) > 0 {
		customMetadataVal, customMetadataDiags := types.MapValueFrom(ctx, types.StringType, apiModel.CustomMetadata)
		diags.Append(customMetadataDiags...)
		if !diags.HasError() {
			data.CustomMetadata = customMetadataVal
		}
	} else {
		data.CustomMetadata = types.MapNull(types.StringType)
	}

	return true
}

func (r *OSSecretBackendAccountResource) buildRequestData(ctx context.Context, data *OSSecretBackendAccountModel, password types.String, includePassword bool) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	requestData := make(map[string]interface{})
	requestData[consts.FieldUsername] = data.Username.ValueString()
	if includePassword {
		requestData[consts.FieldPassword] = password.ValueString()
	}

	if !data.ParentAccountRef.IsNull() && !data.ParentAccountRef.IsUnknown() {
		requestData[consts.FieldParentAccountRef] = data.ParentAccountRef.ValueString()
	} else {
		requestData[consts.FieldParentAccountRef] = ""
	}
	if !data.PasswordPolicy.IsNull() && !data.PasswordPolicy.IsUnknown() {
		requestData[consts.FieldPasswordPolicy] = data.PasswordPolicy.ValueString()
	} else {
		requestData[consts.FieldPasswordPolicy] = ""
	}
	if rotationDiags := frameworkrotation.PopulateAutomatedRotationRequestData(&data.AutomatedRotationModel, requestData); rotationDiags.HasError() {
		diags.Append(rotationDiags...)
		return nil, diags
	}
	if !data.VerifyConnection.IsNull() && !data.VerifyConnection.IsUnknown() {
		requestData[consts.FieldVerifyConnection] = data.VerifyConnection.ValueBool()
	} else {
		requestData[consts.FieldVerifyConnection] = true
	}
	if !data.CustomMetadata.IsNull() && !data.CustomMetadata.IsUnknown() {
		var customMetadata map[string]string
		if mapDiags := data.CustomMetadata.ElementsAs(ctx, &customMetadata, false); mapDiags.HasError() {
			diags.Append(mapDiags...)
			return nil, diags
		}
		requestData[consts.FieldCustomMetadata] = customMetadata
	} else {
		requestData[consts.FieldCustomMetadata] = map[string]string{}
	}

	return requestData, diags
}

func (r *OSSecretBackendAccountResource) writeAccountToVault(ctx context.Context, cli *api.Client, path string, requestData map[string]interface{}, operation string, diags *diag.Diagnostics) bool {
	tflog.Debug(ctx, fmt.Sprintf("OS backend account %s", operation), map[string]any{
		"path": path,
	})
	_, err := cli.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		diags.AddError(
			fmt.Sprintf("Error %s OS secret backend account at %q", operation, path),
			err.Error(),
		)
		return false
	}

	return true
}

func passwordWOUpdated(stateVersion, planVersion types.Int64) bool {
	if stateVersion.IsUnknown() || planVersion.IsUnknown() {
		return false
	}
	if stateVersion.IsNull() != planVersion.IsNull() {
		return true
	}
	if stateVersion.IsNull() {
		return false
	}

	return stateVersion.ValueInt64() != planVersion.ValueInt64()
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

	var passwordWO types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldPasswordWO), &passwordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	accountPath := data.vaultPath()
	requestData, diags := r.buildRequestData(ctx, &data, passwordWO, true)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.writeAccountToVault(ctx, cli, accountPath, requestData, "writing", &resp.Diagnostics) {
		return
	}

	// Read back the configuration (password will not be read back)
	found := r.readAccountFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(
			"Resource not found after creation",
			fmt.Sprintf("Account %q was not found at %q after creation", data.Name.ValueString(), accountPath),
		)
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

	found := r.readAccountFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		// Resource was deleted outside Terraform - remove from state
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *OSSecretBackendAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var stateData OSSecretBackendAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &stateData)...)
	if resp.Diagnostics.HasError() {
		return
	}

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

	accountPath := data.vaultPath()
	includePassword := passwordWOUpdated(stateData.PasswordWOVersion, data.PasswordWOVersion)
	passwordWO := types.StringNull()
	if includePassword {
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldPasswordWO), &passwordWO)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if passwordWO.IsNull() || passwordWO.IsUnknown() {
			resp.Diagnostics.AddError(
				"Missing password_wo",
				"password_wo must be provided whenever password_wo_version changes.",
			)
			return
		}
	}

	requestData, diags := r.buildRequestData(ctx, &data, passwordWO, includePassword)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.writeAccountToVault(ctx, cli, accountPath, requestData, "updating", &resp.Diagnostics) {
		return
	}

	// Read back the configuration (password will not be read back)
	found := r.readAccountFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(
			"Resource not found after update",
			fmt.Sprintf("Account %q was not found at %q after update", data.Name.ValueString(), accountPath),
		)
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

	accountPath := data.vaultPath()
	tflog.Debug(ctx, "Deleting OS backend account", map[string]any{
		"path": accountPath,
	})

	_, err = cli.Logical().DeleteWithContext(ctx, accountPath)
	if err != nil && !util.Is404(err) {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error deleting OS secret backend account at %q", accountPath),
			err.Error(),
		)
	}
}

func (r *OSSecretBackendAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Parse the ID: {mount}/hosts/{host}/accounts/{name}
	mount, host, name, err := parseAccountID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s", req.ID, err.Error()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldHost), host)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)

	// Password must be set after import since it's write-only
	// Set it to a placeholder that will force user to update
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldPasswordWO), "IMPORT_PLACEHOLDER_UPDATE_REQUIRED")...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

// Made with Bob
