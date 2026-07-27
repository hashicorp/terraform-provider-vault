// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package cert

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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
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
	"github.com/hashicorp/terraform-provider-vault/util"
)

var tpmRoleRegexp = regexp.MustCompile(`^auth/(.+)/tpmrole/(.+)$`)

var _ resource.ResourceWithImportState = &AuthCertTPMRoleResource{}

func NewAuthCertTPMRoleResource() resource.Resource {
	return &AuthCertTPMRoleResource{}
}

type AuthCertTPMRoleResource struct {
	base.ResourceWithConfigure
}

type AuthCertTPMRoleModel struct {
	token.TokenModel

	Backend     types.String `tfsdk:"backend"`
	Name        types.String `tfsdk:"name"`
	DisplayName types.String `tfsdk:"display_name"`
	EntityIDs   types.Set    `tfsdk:"entity_ids"`
	GroupIDs    types.Set    `tfsdk:"group_ids"`
}

type authCertTPMRoleAPIModel struct {
	token.TokenAPIModel `mapstructure:",squash"`

	DisplayName string   `json:"display_name" mapstructure:"display_name"`
	EntityIDs   []string `json:"entity_ids" mapstructure:"entity_ids"`
	GroupIDs    []string `json:"group_ids" mapstructure:"group_ids"`
}

func (r *AuthCertTPMRoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cert_auth_backend_tpm_role"
}

func (r *AuthCertTPMRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("cert"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Cert auth backend mount path.",
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
				Description: "A display name for the role.",
			},
			"entity_ids": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Set of entity IDs that are members of this TPM role.",
			},
			"group_ids": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Set of group IDs that are members of this TPM role.",
			},
		},
	}

	token.MustAddBaseAndTokenSchemas(&resp.Schema)
}

func (r *AuthCertTPMRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AuthCertTPMRoleModel
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

	rolePath, err := r.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

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

func (r *AuthCertTPMRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AuthCertTPMRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	rolePath, err := r.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

	roleResp, err := vaultClient.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if roleResp == nil {
		tflog.Warn(ctx, "cert auth TPM role not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, roleResp)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AuthCertTPMRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AuthCertTPMRoleModel
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

	rolePath, err := r.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

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

func (r *AuthCertTPMRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AuthCertTPMRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	rolePath, err := r.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

	if _, err := vaultClient.Logical().DeleteWithContext(ctx, rolePath); err != nil {
		if util.Is404(err) {
			return
		}
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
	}
}

func (r *AuthCertTPMRoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	backend, roleName, err := extractTPMRoleIdentifiers(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s", req.ID, err.Error()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldBackend), backend)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), roleName)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

func (r *AuthCertTPMRoleResource) path(data *AuthCertTPMRoleModel) (string, error) {
	backend := data.Backend.ValueString()
	name := data.Name.ValueString()
	if backend == "" || name == "" {
		return "", fmt.Errorf("backend and name are required fields got backend: %q name: %q", backend, name)
	}
	return fmt.Sprintf("auth/%s/tpmrole/%s", backend, name), nil
}

func (r *AuthCertTPMRoleResource) getAPIModel(ctx context.Context, data *AuthCertTPMRoleModel) (map[string]any, diag.Diagnostics) {
	apiModel := authCertTPMRoleAPIModel{
		DisplayName: data.DisplayName.ValueString(),
	}

	var entityIDs []string
	if diags := data.EntityIDs.ElementsAs(ctx, &entityIDs, false); diags.HasError() {
		return nil, diags
	}
	apiModel.EntityIDs = entityIDs

	var groupIDs []string
	if diags := data.GroupIDs.ElementsAs(ctx, &groupIDs, false); diags.HasError() {
		return nil, diags
	}
	apiModel.GroupIDs = groupIDs

	if diags := token.PopulateTokenAPIFromModel(ctx, &data.TokenModel, &apiModel.TokenAPIModel); diags.HasError() {
		return nil, diags
	}

	var requestBody map[string]any
	if err := mapstructure.Decode(apiModel, &requestBody); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode cert auth TPM role API model to map", err.Error()),
		}
	}

	if len(entityIDs) == 0 {
		delete(requestBody, "entity_ids")
	}
	if len(groupIDs) == 0 {
		delete(requestBody, "group_ids")
	}
	if apiModel.DisplayName == "" {
		delete(requestBody, consts.FieldDisplayName)
	}

	return requestBody, nil
}

func (r *AuthCertTPMRoleResource) populateDataModelFromAPI(ctx context.Context, data *AuthCertTPMRoleModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp authCertTPMRoleAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}

	if readResp.DisplayName == "" {
		data.DisplayName = types.StringNull()
	} else {
		data.DisplayName = types.StringValue(readResp.DisplayName)
	}

	if len(readResp.EntityIDs) == 0 {
		data.EntityIDs = types.SetNull(types.StringType)
	} else {
		entityIDs, diags := types.SetValueFrom(ctx, types.StringType, readResp.EntityIDs)
		if diags.HasError() {
			return diags
		}
		data.EntityIDs = entityIDs
	}

	if len(readResp.GroupIDs) == 0 {
		data.GroupIDs = types.SetNull(types.StringType)
	} else {
		groupIDs, diags := types.SetValueFrom(ctx, types.StringType, readResp.GroupIDs)
		if diags.HasError() {
			return diags
		}
		data.GroupIDs = groupIDs
	}

	return token.PopulateTokenModelFromAPI(ctx, &data.TokenModel, &readResp.TokenAPIModel)
}

func extractTPMRoleIdentifiers(id string) (string, string, error) {
	if id == "" {
		return "", "", fmt.Errorf("import identifier cannot be empty")
	}
	id = strings.Trim(id, "/")

	if !tpmRoleRegexp.MatchString(id) {
		return "", "", fmt.Errorf("import identifier must be of the form 'auth/<backend>/tpmrole/<name>', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	matches := tpmRoleRegexp.FindStringSubmatch(id)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("import identifier must be of the form 'auth/<backend>/tpmrole/<name>', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	backend := strings.TrimSpace(matches[1])
	if backend == "" {
		return "", "", fmt.Errorf("backend cannot be empty")
	}

	name := strings.TrimSpace(matches[2])
	if name == "" {
		return "", "", fmt.Errorf("name cannot be empty")
	}

	return backend, name, nil
}
