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
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
	"github.com/hashicorp/terraform-provider-vault/internal/framework/token"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var tpmRoleRegexp = regexp.MustCompile(`^auth/(.+)/role/(.+)$`)

var _ resource.ResourceWithImportState = &TPMAuthBackendRoleResource{}

func NewTPMAuthBackendRoleResource() resource.Resource {
	return &TPMAuthBackendRoleResource{}
}

type TPMAuthBackendRoleResource struct {
	base.ResourceWithConfigure
}

type TPMAuthBackendRoleModel struct {
	token.TokenModel

	Mount         types.String `tfsdk:"mount"`
	Name          types.String `tfsdk:"name"`
	DisplayName   types.String `tfsdk:"display_name"`
	CertTTL       types.Int64  `tfsdk:"cert_ttl"`
	TPMIDs        types.Set    `tfsdk:"tpm_ids"`
	TPMNames      types.Set    `tfsdk:"tpm_names"`
	TPMGroupIDs   types.Set    `tfsdk:"tpmgroup_ids"`
	TPMGroupNames types.Set    `tfsdk:"tpmgroup_names"`
}

type tpmRoleAPIModel struct {
	token.TokenAPIModel `mapstructure:",squash"`

	DisplayName   string   `json:"display_name" mapstructure:"display_name"`
	CertTTL       int64    `json:"cert_ttl" mapstructure:"cert_ttl"`
	TPMIDs        []string `json:"tpm_ids,omitempty" mapstructure:"tpm_ids,omitempty"`
	TPMNames      []string `json:"tpm_names,omitempty" mapstructure:"tpm_names,omitempty"`
	TPMGroupIDs   []string `json:"tpmgroup_ids,omitempty" mapstructure:"tpmgroup_ids,omitempty"`
	TPMGroupNames []string `json:"tpmgroup_names,omitempty" mapstructure:"tpmgroup_names,omitempty"`
}

func (r *TPMAuthBackendRoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tpm_auth_backend_role"
}

func (r *TPMAuthBackendRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
			consts.FieldCertTTL: schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Certificate TTL for the TPM role, in seconds. Zero means inherit the global `default_cert_ttl` from the backend config.",
			},
			consts.FieldTPMIDs: schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ConflictsWith(path.MatchRoot(consts.FieldTPMNames)),
					setvalidator.AtLeastOneOf(
						path.MatchRoot(consts.FieldTPMIDs),
						path.MatchRoot(consts.FieldTPMNames),
						path.MatchRoot(consts.FieldTPMGroupIDs),
						path.MatchRoot(consts.FieldTPMGroupNames),
					),
					setvalidator.SizeAtLeast(1),
				},
				Description: "Set of TPM record IDs authorized to authenticate with this role.",
			},
			consts.FieldTPMNames: schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ConflictsWith(path.MatchRoot(consts.FieldTPMIDs)),
					setvalidator.AtLeastOneOf(
						path.MatchRoot(consts.FieldTPMIDs),
						path.MatchRoot(consts.FieldTPMNames),
						path.MatchRoot(consts.FieldTPMGroupIDs),
						path.MatchRoot(consts.FieldTPMGroupNames),
					),
					setvalidator.SizeAtLeast(1),
				},
				Description: "Set of TPM record names authorized to authenticate with this role.",
			},
			consts.FieldTPMGroupIDs: schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ConflictsWith(path.MatchRoot(consts.FieldTPMGroupNames)),
					setvalidator.AtLeastOneOf(
						path.MatchRoot(consts.FieldTPMIDs),
						path.MatchRoot(consts.FieldTPMNames),
						path.MatchRoot(consts.FieldTPMGroupIDs),
						path.MatchRoot(consts.FieldTPMGroupNames),
					),
					setvalidator.SizeAtLeast(1),
				},
				Description: "Set of TPM group IDs authorized to authenticate with this role.",
			},
			consts.FieldTPMGroupNames: schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ConflictsWith(path.MatchRoot(consts.FieldTPMGroupIDs)),
					setvalidator.AtLeastOneOf(
						path.MatchRoot(consts.FieldTPMIDs),
						path.MatchRoot(consts.FieldTPMNames),
						path.MatchRoot(consts.FieldTPMGroupIDs),
						path.MatchRoot(consts.FieldTPMGroupNames),
					),
					setvalidator.SizeAtLeast(1),
				},
				Description: "Set of TPM group names authorized to authenticate with this role.",
			},
		},
	}

	token.MustAddBaseAndTokenSchemas(&resp.Schema)
}

func (r *TPMAuthBackendRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data TPMAuthBackendRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !provider.IsEnterpriseSupported(r.Meta()) {
		resp.Diagnostics.AddError("Unsupported Vault edition", "TPM auth backend requires Vault Enterprise.")
		return
	}
	// Check if Vault version supports TPM auth (requires 2.2.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion220) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			fmt.Sprintf("TPM auth backend requires Vault version %s or later.", provider.VaultVersion220),
		)
		return
	}
	resp.Diagnostics.Append(r.checkNamesSupported(&data)...)
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

func (r *TPMAuthBackendRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data TPMAuthBackendRoleModel
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

func (r *TPMAuthBackendRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data TPMAuthBackendRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.checkNamesSupported(&data)...)
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

func (r *TPMAuthBackendRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data TPMAuthBackendRoleModel
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

func (r *TPMAuthBackendRoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *TPMAuthBackendRoleResource) path(data *TPMAuthBackendRoleModel) string {
	return fmt.Sprintf("auth/%s/role/%s", data.Mount.ValueString(), data.Name.ValueString())
}

// checkNamesSupported returns an error diagnostic when tpm_names or tpmgroup_names is
// configured against a Vault version that does not support resolving identity names.
func (r *TPMAuthBackendRoleResource) checkNamesSupported(data *TPMAuthBackendRoleModel) diag.Diagnostics {
	var diags diag.Diagnostics

	hasTPMNames := !data.TPMNames.IsNull() && !data.TPMNames.IsUnknown()
	hasGroupNames := !data.TPMGroupNames.IsNull() && !data.TPMGroupNames.IsUnknown()

	if (hasTPMNames || hasGroupNames) && !r.Meta().IsAPISupported(provider.VaultVersion223) {
		diags.AddError(
			"Feature Not Supported",
			fmt.Sprintf("Specifying identity names (tpm_names and tpmgroup_names) instead of IDs requires Vault version %s or later.", provider.VaultVersion223),
		)
	}
	return diags
}

func (r *TPMAuthBackendRoleResource) getAPIModel(ctx context.Context, data *TPMAuthBackendRoleModel) (map[string]any, diag.Diagnostics) {
	apiModel := tpmRoleAPIModel{
		DisplayName: data.DisplayName.ValueString(),
		CertTTL:     data.CertTTL.ValueInt64(),
	}

	if diags := data.TPMIDs.ElementsAs(ctx, &apiModel.TPMIDs, false); diags.HasError() {
		return nil, diags
	}
	if diags := data.TPMNames.ElementsAs(ctx, &apiModel.TPMNames, false); diags.HasError() {
		return nil, diags
	}
	if diags := data.TPMGroupIDs.ElementsAs(ctx, &apiModel.TPMGroupIDs, false); diags.HasError() {
		return nil, diags
	}
	if diags := data.TPMGroupNames.ElementsAs(ctx, &apiModel.TPMGroupNames, false); diags.HasError() {
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

	// When neither TPM names nor TPM IDs are configured (e.g. the role only uses group
	// associations, or tpm_ids was removed on update), explicitly send an empty tpm_ids list
	// so Vault clears any previously configured TPM IDs instead of leaving them untouched.
	if len(apiModel.TPMNames) == 0 && len(apiModel.TPMIDs) == 0 {
		requestBody[consts.FieldTPMIDs] = []string{}
	}

	// Symmetrically, if neither group names nor group IDs are configured, explicitly send
	// an empty tpmgroup_ids list so Vault clears any previously configured group IDs.
	if len(apiModel.TPMGroupNames) == 0 && len(apiModel.TPMGroupIDs) == 0 {
		requestBody[consts.FieldTPMGroupIDs] = []string{}
	}

	return requestBody, nil
}

func (r *TPMAuthBackendRoleResource) populateDataModelFromAPI(ctx context.Context, data *TPMAuthBackendRoleModel, resp *api.Secret) diag.Diagnostics {
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

	// Vault always returns an integer for cert_ttl (0 when unset). Store whatever Vault
	// returns. 0 is valid and means "inherit default_cert_ttl from the backend config".
	data.CertTTL = types.Int64Value(readResp.CertTTL)

	// TPM identities and groups can be configured either by ID (tpm_ids / tpmgroup_ids)
	// or by Name (tpm_names / tpmgroup_names). These are mutually exclusive representations.
	//
	// We intentionally do NOT mark these fields as Computed in schema:
	// 1. If they were Computed, Vault's readback of both IDs and names would store both in state.
	//    On subsequent updates, getAPIModel would send both fields to Vault, triggering
	//    a "cannot specify both tpm_ids and tpm_names" error from Vault.
	// 2. Omitting a field from config must allow the user to clear/unset it. With Computed: true,
	//    omitting the field would retain the existing value from state rather than removing it.
	//
	// Instead, we inspect which identifier mode the user configured:
	// - If tpm_names is configured, store readResp.TPMNames and ensure tpm_ids is null in state.
	// - If tpm_ids is configured (or neither is set), store readResp.TPMIDs and ensure tpm_names is null.
	// This preserves the user's chosen representation and avoids plan drift or inconsistent result errors.
	//
	// Note: on import there is no prior state to inspect, so IDs are always populated.
	// A role that specifies tpm_names or tpmgroup_names in its terraform config will show an
	// in-place update on the first plan after import. Applying it sends the names to Vault and
	// replaces the IDs in state with names.
	if !data.TPMNames.IsNull() && !data.TPMNames.IsUnknown() {
		if len(readResp.TPMNames) == 0 {
			data.TPMNames = types.SetNull(types.StringType)
		} else {
			tpmNames, diags := types.SetValueFrom(ctx, types.StringType, readResp.TPMNames)
			if diags.HasError() {
				return diags
			}
			data.TPMNames = tpmNames
		}
		data.TPMIDs = types.SetNull(types.StringType)
	} else {
		if len(readResp.TPMIDs) == 0 {
			data.TPMIDs = types.SetNull(types.StringType)
		} else {
			tpmIDs, diags := types.SetValueFrom(ctx, types.StringType, readResp.TPMIDs)
			if diags.HasError() {
				return diags
			}
			data.TPMIDs = tpmIDs
		}
		data.TPMNames = types.SetNull(types.StringType)
	}

	// Apply the same symmetric logic for tpmgroup_names vs tpmgroup_ids.
	if !data.TPMGroupNames.IsNull() && !data.TPMGroupNames.IsUnknown() {
		if len(readResp.TPMGroupNames) == 0 {
			data.TPMGroupNames = types.SetNull(types.StringType)
		} else {
			tpmGroupNames, diags := types.SetValueFrom(ctx, types.StringType, readResp.TPMGroupNames)
			if diags.HasError() {
				return diags
			}
			data.TPMGroupNames = tpmGroupNames
		}
		data.TPMGroupIDs = types.SetNull(types.StringType)
	} else {
		if len(readResp.TPMGroupIDs) == 0 {
			data.TPMGroupIDs = types.SetNull(types.StringType)
		} else {
			tpmGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, readResp.TPMGroupIDs)
			if diags.HasError() {
				return diags
			}
			data.TPMGroupIDs = tpmGroupIDs
		}
		data.TPMGroupNames = types.SetNull(types.StringType)
	}

	return token.PopulateTokenModelFromAPI(ctx, &data.TokenModel, &readResp.TokenAPIModel)
}
