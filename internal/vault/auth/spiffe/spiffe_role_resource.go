// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package spiffe

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
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/token"
	"github.com/hashicorp/vault/api"
)

var roleNameRegexp = regexp.MustCompile("^auth/(.+)/role/(.+)$")

// Ensure the implementation satisfies the resource.ResourceWithImportState interface
var _ resource.ResourceWithImportState = &SpiffeAuthRoleResource{}

// NewSpiffeAuthRoleResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewSpiffeAuthRoleResource() resource.Resource {
	return &SpiffeAuthRoleResource{}
}

// SpiffeAuthRoleResource implements the methods that define this resource
type SpiffeAuthRoleResource struct {
	base.ResourceWithConfigure
}

type SpiffeAuthRoleModel struct {
	token.TokenModel

	Mount              types.String `tfsdk:"mount"`
	Name               types.String `tfsdk:"name"`
	DisplayName        types.String `tfsdk:"display_name"`
	WorkloadIDPatterns types.List   `tfsdk:"workload_id_patterns"`
}

type SpiffeRoleAPIModel struct {
	token.TokenAPIModel `mapstructure:",squash"`

	DisplayName        string   `json:"display_name" mapstructure:"display_name"`
	WorkloadIDPatterns []string `json:"workload_id_patterns" mapstructure:"workload_id_patterns"`
}

func (s *SpiffeAuthRoleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_spiffe_auth_backend_role"
}

func (s *SpiffeAuthRoleResource) Schema(ctx context.Context, request resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Description: "Mount path for the SPIFFE auth engine in Vault.",
				Required:    true,
			},
			consts.FieldName: schema.StringAttribute{
				Description: "Name of the SPIFFE auth role.",
				Required:    true,
			},
			consts.FieldDisplayName: schema.StringAttribute{
				Description: "A display name for the role. This is only used for display " +
					"purposes in Vault, if not provided it will default to the role name.",
				Optional: true,
				Computed: true,
			},
			"workload_id_patterns": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "A comma separated list of patterns that match an incoming workload " +
					"id to this role.  A workload id is the part that remains after stripping the trust domain prefix " +
					"and the slash separator from a spiffe id.",
				Optional: true,
			},
		},
	}

	token.MustAddBaseAndTokenSchemas(&response.Schema)
}

func (s *SpiffeAuthRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SpiffeAuthRoleModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, s.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, diagErr := s.getApiModel(ctx, &data)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	mountPath, err := s.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

	roleResp, err := vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	if roleResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := s.populateDataModelFromApi(ctx, &data, roleResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeAuthRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SpiffeAuthRoleModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, s.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath, err := s.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

	roleResp, err := vaultClient.Logical().ReadWithContext(ctx, mountPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if roleResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := s.populateDataModelFromApi(ctx, &data, roleResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeAuthRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data SpiffeAuthRoleModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, s.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, diagErr := s.getApiModel(ctx, &data)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	mountPath, err := s.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

	roleResp, err := vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	if roleResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := s.populateDataModelFromApi(ctx, &data, roleResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeAuthRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data SpiffeAuthRoleModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, s.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath, err := s.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role path", err.Error())
		return
	}

	if _, err = vaultClient.Logical().Delete(mountPath); err != nil {
		resp.Diagnostics.AddError("Error deleting role", err.Error())
	}
}

func (s *SpiffeAuthRoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount, roleName, err := s.extractSpiffeRoleIdentifiers(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier '%s' is not valid: %s", req.ID, err.Error()),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), roleName)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(
			resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}

func (s *SpiffeAuthRoleResource) path(data *SpiffeAuthRoleModel) (string, error) {
	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	if mount == "" || name == "" {
		return "", fmt.Errorf("mount and name are required fields got mount: %q name: %q", mount, name)
	}
	return fmt.Sprintf("auth/%s/role/%s", mount, name), nil
}

func (s *SpiffeAuthRoleResource) getApiModel(ctx context.Context, data *SpiffeAuthRoleModel) (map[string]any, diag.Diagnostics) {
	apiModel := SpiffeRoleAPIModel{}

	var workloadIdPatterns []string
	if err := data.WorkloadIDPatterns.ElementsAs(ctx, &workloadIdPatterns, false); err != nil {
		return nil, err
	}
	apiModel.WorkloadIDPatterns = workloadIdPatterns

	apiModel.DisplayName = data.DisplayName.ValueString()

	if diagErr := token.PopulateTokenAPIFromModel(ctx, &data.TokenModel, &apiModel.TokenAPIModel); diagErr.HasError() {
		return nil, diagErr
	}

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode SPIFFE role API model to map", err.Error()),
		}
	}

	return vaultRequest, nil
}

func (s *SpiffeAuthRoleResource) populateDataModelFromApi(ctx context.Context, role *SpiffeAuthRoleModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp SpiffeRoleAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}

	if len(readResp.WorkloadIDPatterns) > 0 {
		wkldIdPatterns, listErr := types.ListValueFrom(ctx, types.StringType, readResp.WorkloadIDPatterns)
		if listErr != nil {
			return listErr
		}
		role.WorkloadIDPatterns = wkldIdPatterns
	}

	role.DisplayName = types.StringValue(readResp.DisplayName)

	return token.PopulateTokenModelFromAPI(ctx, &role.TokenModel, &readResp.TokenAPIModel)
}

func (s *SpiffeAuthRoleResource) extractSpiffeRoleIdentifiers(id string) (string, string, error) {
	if id == "" {
		return "", "", fmt.Errorf("import identifier cannot be empty")
	}
	// Trim leading slash if present
	id = strings.Trim(id, "/")

	if !roleNameRegexp.MatchString(id) {
		return "", "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/role/<rolename>', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	matches := roleNameRegexp.FindStringSubmatch(id)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/role/<rolename>', "+
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
