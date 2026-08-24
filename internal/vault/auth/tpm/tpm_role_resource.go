// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/token"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var tpmRoleRegexp = regexp.MustCompile(`^auth/(.+)/role/(.+)$`)

var _ resource.ResourceWithImportState = &TPMAuthRoleResource{}

func NewTPMAuthRoleResource() resource.Resource {
	return &TPMAuthRoleResource{}
}

type TPMAuthRoleResource struct {
	base.ResourceWithConfigure
}

type TPMAuthRoleModel struct {
	token.TokenModel

	Mount       types.String `tfsdk:"mount"`
	Name        types.String `tfsdk:"name"`
	DisplayName types.String `tfsdk:"display_name"`
	CertTTL     types.String `tfsdk:"cert_ttl"`
	TPMIDs      types.Set    `tfsdk:"tpm_ids"`
	TPMGroupIDs types.Set    `tfsdk:"tpmgroup_ids"`
}

type tpmRoleAPIModel struct {
	token.TokenAPIModel `mapstructure:",squash"`

	DisplayName string   `json:"display_name" mapstructure:"display_name"`
	CertTTL     string   `json:"cert_ttl" mapstructure:"cert_ttl"`
	TPMIDs      []string `json:"tpm_ids" mapstructure:"tpm_ids"`
	TPMGroupIDs []string `json:"tpmgroup_ids" mapstructure:"tpmgroup_ids"`
}

func (r *TPMAuthRoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tpm_auth_backend_role"
}

func (r *TPMAuthRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "TPM auth backend mount path.",
			},
			consts.FieldName: schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Name of the TPM role.",
			},
			consts.FieldDisplayName: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Display name for the role. Defaults to the role name.",
			},
			consts.FieldCertTTL: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Certificate TTL for the TPM role.",
			},
			"tpm_ids": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Set of TPM record IDs authorized to authenticate with this role.",
			},
			"tpmgroup_ids": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Set of TPM group IDs authorized to authenticate with this role.",
			},
		},
	}

	token.MustAddBaseAndTokenSchemas(&resp.Schema)
}

func (r *TPMAuthRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data TPMAuthRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if Vault version supports TMP auth (requires 2.2.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion220) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			fmt.Sprintf("TPM auth backend requires Vault version %s or later. Current Vault version: %s", provider.VaultVersion220, r.Meta().GetVaultVersion().String()),
		)
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	requestBody, diags := r.getAPIModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	rolePath := r.path(&data)
	if _, err := vaultClient.Logical().WriteWithContext(ctx, rolePath, requestBody); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	roleResp, err := vaultClient.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if roleResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, roleResp)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TPMAuthRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data TPMAuthRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	roleResp, err := vaultClient.Logical().ReadWithContext(ctx, r.path(&data))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if roleResp == nil {
		tflog.Warn(ctx, "TPM role not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, roleResp)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TPMAuthRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data TPMAuthRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	requestBody, diags := r.getAPIModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	rolePath := r.path(&data)
	if _, err := vaultClient.Logical().WriteWithContext(ctx, rolePath, requestBody); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	roleResp, err := vaultClient.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if roleResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, roleResp)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TPMAuthRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data TPMAuthRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if _, err := vaultClient.Logical().DeleteWithContext(ctx, r.path(&data)); err != nil {
		if util.Is404(err) {
			return
		}
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
	}
}

func (r *TPMAuthRoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount, name, err := extractTPMRoleIdentifiers(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import identifier",
			fmt.Sprintf("Expected format: auth/<mount>/role/<name>. Got: %q. Error: %s", req.ID, err))
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

	vaultClient, err := client.GetClient(ctx, r.Meta(), ns)
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	roleResp, err := vaultClient.Logical().ReadWithContext(ctx, fmt.Sprintf("auth/%s/role/%s", strings.Trim(mount, "/"), name))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if roleResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	data := TPMAuthRoleModel{
		Mount: types.StringValue(mount),
		Name:  types.StringValue(name),
	}
	if ns != "" {
		data.Namespace = types.StringValue(ns)
	}
	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, roleResp)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func extractTPMRoleIdentifiers(importID string) (mount, name string, err error) {
	importID = strings.Trim(importID, "/")
	if importID == "" {
		return "", "", fmt.Errorf("import identifier cannot be empty")
	}

	matches := tpmRoleRegexp.FindStringSubmatch("auth/" + strings.TrimPrefix(importID, "auth/"))
	if len(matches) != 3 {
		return "", "", fmt.Errorf("must be of the form auth/<mount>/role/<name>")
	}

	return matches[1], matches[2], nil
}

func (r *TPMAuthRoleResource) path(data *TPMAuthRoleModel) string {
	return fmt.Sprintf("auth/%s/role/%s", data.Mount.ValueString(), data.Name.ValueString())
}

func (r *TPMAuthRoleResource) getAPIModel(ctx context.Context, data *TPMAuthRoleModel) (map[string]any, diag.Diagnostics) {
	apiModel := tpmRoleAPIModel{
		DisplayName: data.DisplayName.ValueString(),
		CertTTL:     data.CertTTL.ValueString(),
	}

	if diags := data.TPMIDs.ElementsAs(ctx, &apiModel.TPMIDs, false); diags.HasError() {
		return nil, diags
	}
	if diags := data.TPMGroupIDs.ElementsAs(ctx, &apiModel.TPMGroupIDs, false); diags.HasError() {
		return nil, diags
	}

	tokenDiags := token.PopulateTokenAPIFromModel(ctx, &data.TokenModel, &apiModel.TokenAPIModel)
	if tokenDiags.HasError() {
		return nil, tokenDiags
	}

	var requestBody map[string]any
	if err := mapstructure.Decode(apiModel, &requestBody); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode TPM role API model to map", err.Error()),
		}
	}

	return requestBody, nil
}

func (r *TPMAuthRoleResource) populateDataModelFromAPI(ctx context.Context, data *TPMAuthRoleModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp tpmRoleAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}

	data.DisplayName = types.StringValue(readResp.DisplayName)
	if readResp.CertTTL == "" {
		if data.CertTTL.IsNull() || data.CertTTL.IsUnknown() {
			data.CertTTL = types.StringNull()
		}
	} else {
		data.CertTTL = types.StringValue(readResp.CertTTL)
	}

	if len(readResp.TPMIDs) == 0 {
		data.TPMIDs = types.SetNull(types.StringType)
	} else {
		tpmIDs, diags := types.SetValueFrom(ctx, types.StringType, readResp.TPMIDs)
		if diags.HasError() {
			return diags
		}
		data.TPMIDs = tpmIDs
	}

	if len(readResp.TPMGroupIDs) == 0 {
		data.TPMGroupIDs = types.SetNull(types.StringType)
	} else {
		tpmGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, readResp.TPMGroupIDs)
		if diags.HasError() {
			return diags
		}
		data.TPMGroupIDs = tpmGroupIDs
	}

	return token.PopulateTokenModelFromAPI(ctx, &data.TokenModel, &readResp.TokenAPIModel)
}
