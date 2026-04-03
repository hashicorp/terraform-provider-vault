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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
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
	frameworkrotation "github.com/hashicorp/terraform-provider-vault/internal/framework/rotation"
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
	base.BaseModel

	Mount          types.String `tfsdk:"mount"`
	Name           types.String `tfsdk:"name"`
	Address        types.String `tfsdk:"address"`
	Port           types.Int64  `tfsdk:"port"`
	SSHHostKey     types.String `tfsdk:"ssh_host_key"`
	PasswordPolicy types.String `tfsdk:"password_policy"`
	frameworkrotation.AutomatedRotationModel
	CustomMetadata types.Map `tfsdk:"custom_metadata"`
}

// OSSecretBackendHostAPIModel describes the Vault API data model
type OSSecretBackendHostAPIModel struct {
	Address        string `json:"address" mapstructure:"address"`
	Port           int64  `json:"port,omitempty" mapstructure:"port"`
	SSHHostKey     string `json:"ssh_host_key,omitempty" mapstructure:"ssh_host_key"`
	PasswordPolicy string `json:"password_policy,omitempty" mapstructure:"password_policy"`
	frameworkrotation.AutomatedRotationAPIModel
	CustomMetadata map[string]string `json:"custom_metadata,omitempty" mapstructure:"custom_metadata"`
}

func (m OSSecretBackendHostModel) vaultPath() string {
	return fmt.Sprintf("%s/hosts/%s", m.Mount.ValueString(), m.Name.ValueString())
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
				Computed:            true,
			},
			consts.FieldPasswordPolicy: schema.StringAttribute{
				MarkdownDescription: "Name of the password policy to use for password generation.",
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
	frameworkrotation.MustAddAutomatedRotationSchemas(&resp.Schema)
}

// readHostFromVault reads the host configuration from Vault and populates the model
func (r *OSSecretBackendHostResource) readHostFromVault(ctx context.Context, cli *api.Client, data *OSSecretBackendHostModel, diags *diag.Diagnostics) {
	path := data.vaultPath()

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
	data.Address = types.StringValue(apiModel.Address)
	if apiModel.Port != 0 {
		data.Port = types.Int64Value(apiModel.Port)
	} else {
		data.Port = types.Int64Null()
	}
	if apiModel.SSHHostKey != "" {
		data.SSHHostKey = types.StringValue(apiModel.SSHHostKey)
	} else {
		data.SSHHostKey = types.StringNull()
	}
	if apiModel.PasswordPolicy != "" {
		data.PasswordPolicy = types.StringValue(apiModel.PasswordPolicy)
	} else {
		data.PasswordPolicy = types.StringNull()
	}
	rotationModel := frameworkrotation.AutomatedRotationModel{
		RotationPeriod:           data.RotationPeriod,
		RotationSchedule:         data.RotationSchedule,
		RotationWindow:           data.RotationWindow,
		DisableAutomatedRotation: data.DisableAutomatedRotation,
	}
	rotationAPIModel := frameworkrotation.AutomatedRotationAPIModel(apiModel.AutomatedRotationAPIModel)
	diags.Append(frameworkrotation.PopulateAutomatedRotationModelFromAPI(&rotationModel, &rotationAPIModel)...)
	if diags.HasError() {
		return
	}
	data.AutomatedRotationModel = rotationModel

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
}

func (r *OSSecretBackendHostResource) buildRequestData(ctx context.Context, data *OSSecretBackendHostModel) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	requestData := make(map[string]interface{})
	requestData[consts.FieldAddress] = data.Address.ValueString()

	if !data.Port.IsNull() && !data.Port.IsUnknown() {
		requestData[consts.FieldPort] = data.Port.ValueInt64()
	} else {
		requestData[consts.FieldPort] = 0
	}
	if !data.SSHHostKey.IsNull() && !data.SSHHostKey.IsUnknown() {
		requestData[consts.FieldSSHHostKey] = data.SSHHostKey.ValueString()
	} else {
		requestData[consts.FieldSSHHostKey] = ""
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

func (r *OSSecretBackendHostResource) writeHostToVault(ctx context.Context, cli *api.Client, path string, requestData map[string]interface{}, operation string, diags *diag.Diagnostics) bool {
	_, err := cli.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		diags.AddError(
			fmt.Sprintf("Error %s OS secret backend host at %q", operation, path),
			err.Error(),
		)
		return false
	}

	return true
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

	path := data.vaultPath()
	requestData, diags := r.buildRequestData(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.writeHostToVault(ctx, cli, path, requestData, "writing", &resp.Diagnostics) {
		return
	}

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

	path := data.vaultPath()
	requestData, diags := r.buildRequestData(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.writeHostToVault(ctx, cli, path, requestData, "updating", &resp.Diagnostics) {
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

	path := data.vaultPath()

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
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s", req.ID, err.Error()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)

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
