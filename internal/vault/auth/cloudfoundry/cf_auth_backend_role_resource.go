// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudfoundry

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
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/token"
)

var cfRoleRegexp = regexp.MustCompile(`^auth/(.+)/roles/(.+)$`)

// Ensure the implementation satisfies the resource.ResourceWithImportState interface.
var _ resource.ResourceWithImportState = &CFAuthBackendRoleResource{}

// NewCFAuthBackendRoleResource returns the implementation for this resource.
func NewCFAuthBackendRoleResource() resource.Resource {
	return &CFAuthBackendRoleResource{}
}

// CFAuthBackendRoleResource implements the Terraform Plugin Framework resource.
type CFAuthBackendRoleResource struct {
	base.ResourceWithConfigure
}

// CFAuthBackendRoleModel describes the Terraform resource data model.
type CFAuthBackendRoleModel struct {
	token.TokenModel

	Mount                types.String `tfsdk:"mount"`
	Name                 types.String `tfsdk:"name"`
	BoundApplicationIDs  types.List   `tfsdk:"bound_application_ids"`
	BoundSpaceIDs        types.List   `tfsdk:"bound_space_ids"`
	BoundOrganizationIDs types.List   `tfsdk:"bound_organization_ids"`
	BoundInstanceIDs     types.List   `tfsdk:"bound_instance_ids"`
	DisableIPMatching    types.Bool   `tfsdk:"disable_ip_matching"`
}

// CFRoleAPIModel describes the Vault API data model.
type CFRoleAPIModel struct {
	token.TokenAPIModel `mapstructure:",squash"`

	BoundApplicationIDs  []string `json:"bound_application_ids" mapstructure:"bound_application_ids"`
	BoundSpaceIDs        []string `json:"bound_space_ids" mapstructure:"bound_space_ids"`
	BoundOrganizationIDs []string `json:"bound_organization_ids" mapstructure:"bound_organization_ids"`
	BoundInstanceIDs     []string `json:"bound_instance_ids" mapstructure:"bound_instance_ids"`
	DisableIPMatching    bool     `json:"disable_ip_matching" mapstructure:"disable_ip_matching"`
}

func (r *CFAuthBackendRoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cf_auth_backend_role"
}

func (r *CFAuthBackendRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a role for the CloudFoundry (CF) auth method in Vault.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the CF auth engine in Vault.",
				Required:            true,
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the CF auth role.",
				Required:            true,
			},
			"bound_application_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "An optional list of application IDs an instance must be a member of to qualify for this role.",
				Optional:            true,
			},
			"bound_space_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "An optional list of space IDs an instance must be a member of to qualify for this role.",
				Optional:            true,
			},
			"bound_organization_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "An optional list of organization IDs an instance must be a member of to qualify for this role.",
				Optional:            true,
			},
			"bound_instance_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "An optional list of instance IDs an instance must be a member of to qualify for this role.",
				Optional:            true,
			},
			"disable_ip_matching": schema.BoolAttribute{
				MarkdownDescription: "If set to true, disables the default behavior that logging in must be performed from an acceptable IP address described by the presented certificate.",
				Optional:            true,
				Computed:            true,
			},
		},
	}

	token.MustAddBaseAndTokenSchemas(&resp.Schema)
}

func (r *CFAuthBackendRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data CFAuthBackendRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, diagErr := r.getAPIModel(ctx, &data)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	rolePath, err := r.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

	_, err = vaultClient.Logical().WriteWithContext(ctx, rolePath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Vault returns HTTP 204 with no body for role writes; read back the role to populate state.
	roleResp, err := vaultClient.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if roleResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := r.populateDataModelFromAPI(ctx, &data, roleResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CFAuthBackendRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data CFAuthBackendRoleModel
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
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := r.populateDataModelFromAPI(ctx, &data, roleResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CFAuthBackendRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data CFAuthBackendRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, diagErr := r.getAPIModel(ctx, &data)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	rolePath, err := r.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

	_, err = vaultClient.Logical().WriteWithContext(ctx, rolePath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Vault returns HTTP 204 with no body for role writes; read back the role to populate state.
	roleResp, err := vaultClient.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if roleResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := r.populateDataModelFromAPI(ctx, &data, roleResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CFAuthBackendRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data CFAuthBackendRoleModel
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

	if _, err := vaultClient.Logical().Delete(rolePath); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
	}
}

func (r *CFAuthBackendRoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount, roleName, err := extractCFRoleIdentifiers(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s", req.ID, err.Error()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), roleName)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

func (r *CFAuthBackendRoleResource) path(data *CFAuthBackendRoleModel) (string, error) {
	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	if mount == "" || name == "" {
		return "", fmt.Errorf("mount and name are required fields; got mount: %q name: %q", mount, name)
	}
	return fmt.Sprintf("auth/%s/roles/%s", mount, name), nil
}

func (r *CFAuthBackendRoleResource) getAPIModel(ctx context.Context, data *CFAuthBackendRoleModel) (map[string]any, diag.Diagnostics) {
	apiModel := CFRoleAPIModel{
		DisableIPMatching: data.DisableIPMatching.ValueBool(),
	}

	var boundAppIDs []string
	if diagErr := data.BoundApplicationIDs.ElementsAs(ctx, &boundAppIDs, false); diagErr.HasError() {
		return nil, diagErr
	}
	apiModel.BoundApplicationIDs = boundAppIDs

	var boundSpaceIDs []string
	if diagErr := data.BoundSpaceIDs.ElementsAs(ctx, &boundSpaceIDs, false); diagErr.HasError() {
		return nil, diagErr
	}
	apiModel.BoundSpaceIDs = boundSpaceIDs

	var boundOrgIDs []string
	if diagErr := data.BoundOrganizationIDs.ElementsAs(ctx, &boundOrgIDs, false); diagErr.HasError() {
		return nil, diagErr
	}
	apiModel.BoundOrganizationIDs = boundOrgIDs

	var boundInstanceIDs []string
	if diagErr := data.BoundInstanceIDs.ElementsAs(ctx, &boundInstanceIDs, false); diagErr.HasError() {
		return nil, diagErr
	}
	apiModel.BoundInstanceIDs = boundInstanceIDs

	if diagErr := token.PopulateTokenAPIFromModel(ctx, &data.TokenModel, &apiModel.TokenAPIModel); diagErr.HasError() {
		return nil, diagErr
	}

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode CF role API model to map", err.Error()),
		}
	}

	return vaultRequest, nil
}

func (r *CFAuthBackendRoleResource) populateDataModelFromAPI(ctx context.Context, data *CFAuthBackendRoleModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp CFRoleAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}

	data.DisableIPMatching = types.BoolValue(readResp.DisableIPMatching)

	if len(readResp.BoundApplicationIDs) == 0 {
		data.BoundApplicationIDs = types.ListNull(types.StringType)
	} else {
		boundAppIDs, listErr := types.ListValueFrom(ctx, types.StringType, readResp.BoundApplicationIDs)
		if listErr.HasError() {
			return listErr
		}
		data.BoundApplicationIDs = boundAppIDs
	}

	if len(readResp.BoundSpaceIDs) == 0 {
		data.BoundSpaceIDs = types.ListNull(types.StringType)
	} else {
		boundSpaceIDs, listErr := types.ListValueFrom(ctx, types.StringType, readResp.BoundSpaceIDs)
		if listErr.HasError() {
			return listErr
		}
		data.BoundSpaceIDs = boundSpaceIDs
	}

	if len(readResp.BoundOrganizationIDs) == 0 {
		data.BoundOrganizationIDs = types.ListNull(types.StringType)
	} else {
		boundOrgIDs, listErr := types.ListValueFrom(ctx, types.StringType, readResp.BoundOrganizationIDs)
		if listErr.HasError() {
			return listErr
		}
		data.BoundOrganizationIDs = boundOrgIDs
	}

	if len(readResp.BoundInstanceIDs) == 0 {
		data.BoundInstanceIDs = types.ListNull(types.StringType)
	} else {
		boundInstanceIDs, listErr := types.ListValueFrom(ctx, types.StringType, readResp.BoundInstanceIDs)
		if listErr.HasError() {
			return listErr
		}
		data.BoundInstanceIDs = boundInstanceIDs
	}

	return token.PopulateTokenModelFromAPI(ctx, &data.TokenModel, &readResp.TokenAPIModel)
}

func extractCFRoleIdentifiers(id string) (string, string, error) {
	if id == "" {
		return "", "", fmt.Errorf("import identifier cannot be empty")
	}
	id = strings.Trim(id, "/")

	if !cfRoleRegexp.MatchString(id) {
		return "", "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/roles/<rolename>', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	matches := cfRoleRegexp.FindStringSubmatch(id)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/roles/<rolename>', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	mount := strings.TrimSpace(matches[1])
	if mount == "" {
		return "", "", fmt.Errorf("mount cannot be empty")
	}

	roleName := strings.TrimSpace(matches[2])
	if roleName == "" {
		return "", "", fmt.Errorf("role name cannot be empty")
	}

	return mount, roleName, nil
}
