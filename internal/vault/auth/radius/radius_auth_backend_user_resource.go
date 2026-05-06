// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package radius

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/vault/api"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &RadiusAuthBackendUserResource{}

// NewRadiusAuthBackendUserResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewRadiusAuthBackendUserResource() resource.Resource {
	return &RadiusAuthBackendUserResource{}
}

// RadiusAuthBackendUserResource implements the methods that define this resource
type RadiusAuthBackendUserResource struct {
	base.ResourceWithConfigure
}

// RadiusAuthBackendUserModel describes the Terraform resource data model to match the
// resource schema.
type RadiusAuthBackendUserModel struct {
	base.BaseModel

	Mount    types.String `tfsdk:"mount"`
	Username types.String `tfsdk:"username"`
	Policies types.Set    `tfsdk:"policies"`
}

// RadiusAuthBackendUserAPIModel describes the Vault API response structure.
type RadiusAuthBackendUserAPIModel struct {
	Policies []string `json:"policies" mapstructure:"policies"`
}

const radiusUserImportIDFormat = "expected import ID in the format auth/<mount>/users/<username>"

// Metadata defines the resource name as it would appear in Terraform configurations
func (r *RadiusAuthBackendUserResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_radius_auth_backend_user"
}

// Schema defines this resource's schema
func (r *RadiusAuthBackendUserResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path to the RADIUS auth mount where the user will be registered.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldUsername: schema.StringAttribute{
				MarkdownDescription: "The username to register with the RADIUS auth backend.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldPolicies: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "A set of Vault policies to associate with this user. If not set, only the `default` policy will be applicable to the user.",
				Optional:            true,
			},
		},
		MarkdownDescription: "Manages a RADIUS user registered with a RADIUS Auth Backend in Vault.",
	}

	// Add the common base schema
	base.MustAddBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *RadiusAuthBackendUserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RadiusAuthBackendUserModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.upsertUser(ctx, &data, errutil.VaultCreateErr)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *RadiusAuthBackendUserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RadiusAuthBackendUserModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, _, _, userPath, diags := r.getClientAndUserData(ctx, data.Namespace.ValueString(), data.Mount, data.Username)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	userResp, readDiags := r.readUser(ctx, vaultClient, userPath)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if userResp == nil {
		tflog.Warn(ctx, fmt.Sprintf("RADIUS user at '%s' not found, removing from state", userPath))
		resp.State.RemoveResource(ctx)
		return
	}

	// Populate model from API response
	populateDiags := r.populateDataModelFromApi(ctx, &data, userResp.Data)
	resp.Diagnostics.Append(populateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command.
func (r *RadiusAuthBackendUserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data RadiusAuthBackendUserModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.upsertUser(ctx, &data, errutil.VaultUpdateErr)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// upsertUser writes the RADIUS user registration and refreshes the Terraform
// model from Vault's read-after-write response.
func (r *RadiusAuthBackendUserResource) upsertUser(ctx context.Context, data *RadiusAuthBackendUserModel, writeErr func(error) (string, string)) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, _, _, userPath, clientDiags := r.getClientAndUserData(ctx, data.Namespace.ValueString(), data.Mount, data.Username)
	diags.Append(clientDiags...)
	if diags.HasError() {
		return diags
	}

	vaultRequest, apiDiags := r.getApiModel(ctx, data)
	diags.Append(apiDiags...)
	if diags.HasError() {
		return diags
	}

	userResp, writeDiags := r.writeUser(ctx, vaultClient, userPath, vaultRequest, writeErr)
	diags.Append(writeDiags...)
	if diags.HasError() {
		return diags
	}

	diags.Append(r.populateDataModelFromApi(ctx, data, userResp.Data)...)
	return diags
}

// Delete is called during the terraform destroy command.
func (r *RadiusAuthBackendUserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RadiusAuthBackendUserModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, _, _, userPath, diags := r.getClientAndUserData(ctx, data.Namespace.ValueString(), data.Mount, data.Username)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Deleting RADIUS user at '%s'", userPath))
	_, err := vaultClient.Logical().DeleteWithContext(ctx, userPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting RADIUS user",
			fmt.Sprintf("Could not delete RADIUS user at '%s': %s", userPath, err),
		)
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Deleted RADIUS user at '%s'", userPath))
}

// ImportState handles resource import
func (r *RadiusAuthBackendUserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	// Parse the import ID using the official Vault API format
	mount, username, err := extractRadiusUserMountAndNameFromID(id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID format",
			fmt.Sprintf("Expected format: 'auth/<mount>/users/<username>', got: '%s'", req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldUsername), username)...)

	// Handle namespace import via environment variable
	// See: https://registry.terraform.io/providers/hashicorp/vault/latest/docs#namespace-support
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

// userPath returns the Vault API path for RADIUS user
func (r *RadiusAuthBackendUserResource) userPath(mount, username string) string {
	return fmt.Sprintf("auth/%s/users/%s", mount, username)
}

// extractRadiusUserMountAndNameFromID parses an import identifier in the form
// auth/<mount>/users/<username>. The username segment intentionally remains
// broad to match Vault's RADIUS route pattern of users/(?P<name>.+).
func extractRadiusUserMountAndNameFromID(id string) (string, string, error) {
	id = strings.Trim(id, "/")
	remainder, ok := strings.CutPrefix(id, "auth/")
	if !ok {
		return "", "", fmt.Errorf(radiusUserImportIDFormat)
	}

	separatorIndex := strings.LastIndex(remainder, "/users/")
	if separatorIndex < 1 {
		return "", "", fmt.Errorf(radiusUserImportIDFormat)
	}

	mount := strings.Trim(remainder[:separatorIndex], "/")
	username := remainder[separatorIndex+len("/users/"):]
	if mount == "" || username == "" || strings.Contains(mount, "//") {
		return "", "", fmt.Errorf(radiusUserImportIDFormat)
	}

	return mount, username, nil
}

// getClientAndUserData returns a Vault client together with normalized mount,
// username, and user path values used by the resource operations.
func (r *RadiusAuthBackendUserResource) getClientAndUserData(ctx context.Context, namespace string, mount types.String, username types.String) (*api.Client, string, string, string, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), namespace)
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return nil, "", "", "", diags
	}

	mountPath := strings.Trim(mount.ValueString(), "/")
	userName := strings.Trim(username.ValueString(), "/")
	userPath := r.userPath(mountPath, userName)

	return vaultClient, mountPath, userName, userPath, diags
}

// writeUser writes the RADIUS user entry and then reads it back so Terraform
// state matches the values returned by Vault.
func (r *RadiusAuthBackendUserResource) writeUser(ctx context.Context, vaultClient *api.Client, userPath string, vaultRequest map[string]any, writeErr func(error) (string, string)) (*api.Secret, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, fmt.Sprintf("Writing RADIUS user to '%s'", userPath))
	_, err := vaultClient.Logical().WriteWithContext(ctx, userPath, vaultRequest)
	if err != nil {
		diags.AddError(writeErr(err))
		return nil, diags
	}
	tflog.Info(ctx, fmt.Sprintf("RADIUS user successfully written to '%s'", userPath))

	userResp, readDiags := r.readUser(ctx, vaultClient, userPath)
	diags.Append(readDiags...)
	if diags.HasError() {
		return nil, diags
	}
	if userResp == nil {
		diags.AddError(errutil.VaultReadResponseNil())
		return nil, diags
	}

	return userResp, diags
}

// readUser reads a RADIUS user registration from Vault.
func (r *RadiusAuthBackendUserResource) readUser(ctx context.Context, vaultClient *api.Client, userPath string) (*api.Secret, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, fmt.Sprintf("Reading RADIUS user from '%s'", userPath))
	userResp, err := vaultClient.Logical().ReadWithContext(ctx, userPath)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return nil, diags
	}

	return userResp, diags
}

// getApiModel builds the Vault API request map from the Terraform data model.
func (r *RadiusAuthBackendUserResource) getApiModel(ctx context.Context, data *RadiusAuthBackendUserModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Convert Set to comma-separated string for Vault API
	// Note: Vault RADIUS API accepts comma-separated string but returns array
	vaultRequest := map[string]any{}
	if !data.Policies.IsNull() && !data.Policies.IsUnknown() {
		var elements []string
		elementsDiags := data.Policies.ElementsAs(ctx, &elements, false)
		diags.Append(elementsDiags...)
		if diags.HasError() {
			return nil, diags
		}
		if len(elements) > 0 {
			policiesStr := strings.Join(elements, ",")
			vaultRequest[consts.FieldPolicies] = policiesStr
		}
	}

	return vaultRequest, diags
}

// populateDataModelFromApi maps the Vault API response to the Terraform data model.
func (r *RadiusAuthBackendUserResource) populateDataModelFromApi(ctx context.Context, data *RadiusAuthBackendUserModel, respData map[string]any) diag.Diagnostics {
	var diags diag.Diagnostics

	if respData == nil {
		diags.AddError("Missing data in API response", "The API response data was nil.")
		return diags
	}

	// Decode API response into API model using model.ToAPIModel
	var apiModel RadiusAuthBackendUserAPIModel
	if err := model.ToAPIModel(respData, &apiModel); err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return diags
	}

	// Convert policies from API model to Terraform model
	if len(apiModel.Policies) > 0 {
		policies, setDiags := types.SetValueFrom(ctx, types.StringType, apiModel.Policies)
		diags.Append(setDiags...)
		if diags.HasError() {
			return diags
		}
		data.Policies = policies
	} else {
		// When Vault returns no policies, clear the Terraform state to avoid stale values.
		data.Policies = types.SetNull(types.StringType)
	}
	return diags
}
