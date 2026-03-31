// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
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

var userRegexp = regexp.MustCompile(`^auth/(.+)/users/(.+)$`)
var bcryptHashRegexp = regexp.MustCompile(`^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$`)

var _ resource.ResourceWithImportState = &UserpassAuthUserResource{}

func NewUserpassAuthUserResource() resource.Resource {
	return &UserpassAuthUserResource{}
}

type UserpassAuthUserResource struct {
	base.ResourceWithConfigure
}

type UserpassAuthUserModel struct {
	token.TokenModel

	Mount          types.String `tfsdk:"mount"`
	Username       types.String `tfsdk:"username"`
	PasswordWO     types.String `tfsdk:"password_wo"`
	PasswordHashWO types.String `tfsdk:"password_hash_wo"`
}

type UserpassAuthUserAPIModel struct {
	token.TokenAPIModel `mapstructure:",squash"`
}

func (r *UserpassAuthUserResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_userpass_auth_backend_user"
}

func (r *UserpassAuthUserResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a user for the Userpass auth method in Vault.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the Userpass auth engine in Vault.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldUsername: schema.StringAttribute{
				MarkdownDescription: "Username for this Userpass user.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldPasswordWO: schema.StringAttribute{
				MarkdownDescription: "Password for this user. This is a write-only field and will not be read back from Vault.",
				Optional:            true,
				Sensitive:           true,
				WriteOnly:           true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName(consts.FieldPasswordHashWO)),
					stringvalidator.ExactlyOneOf(path.MatchRelative().AtParent().AtName(consts.FieldPasswordHashWO)),
				},
			},
			consts.FieldPasswordHashWO: schema.StringAttribute{
				MarkdownDescription: "Pre-hashed password for this user in bcrypt format. Available in Vault 1.17 and later. Mutually exclusive with password_wo.",
				Optional:            true,
				Sensitive:           true,
				WriteOnly:           true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName(consts.FieldPasswordWO)),
					stringvalidator.ExactlyOneOf(path.MatchRelative().AtParent().AtName(consts.FieldPasswordWO)),
					stringvalidator.RegexMatches(bcryptHashRegexp, "must be a bcrypt hash"),
				},
			},
		},
	}

	token.MustAddBaseAndTokenSchemas(&resp.Schema)
}

func (r *UserpassAuthUserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data UserpassAuthUserModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.upsertUser(ctx, &data, req.Config, errutil.VaultCreateErr)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserpassAuthUserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data UserpassAuthUserModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, diags := r.getVaultClient(ctx, data.Namespace)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	userResp, diags := r.readUser(ctx, vaultClient, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if userResp == nil {
		tflog.Warn(ctx, "Userpass auth backend user not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	if diagErr := r.populateDataModelFromAPI(ctx, &data, userResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserpassAuthUserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data UserpassAuthUserModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.upsertUser(ctx, &data, req.Config, errutil.VaultUpdateErr)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserpassAuthUserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data UserpassAuthUserModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if _, err := vaultClient.Logical().DeleteWithContext(ctx, r.userPath(data.Mount.ValueString(), data.Username.ValueString())); err != nil {
		if util.Is404(err) {
			return
		}
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
	}
}

func (r *UserpassAuthUserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount, username, err := extractUserpassUserIdentifiers(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s", req.ID, err.Error()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldUsername), username)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

// userPath builds the Userpass user endpoint and optional sub-endpoints.
func (r *UserpassAuthUserResource) userPath(mount, username string, suffix ...string) string {
	parts := []string{"auth", mount, "users", username}
	parts = append(parts, suffix...)
	return strings.Join(parts, "/")
}

func (r *UserpassAuthUserResource) supportsAliasMetadata() bool {
	meta := r.Meta()
	return meta != nil && meta.IsAPISupported(provider.VaultVersion121) && meta.IsEnterpriseSupported()
}

// readCredentialsFromConfig reads credential attributes directly from config.
func (r *UserpassAuthUserResource) readCredentialsFromConfig(ctx context.Context, config tfsdk.Config) (types.String, types.String, diag.Diagnostics) {
	var diags diag.Diagnostics

	var passwordWO types.String
	diags.Append(config.GetAttribute(ctx, path.Root(consts.FieldPasswordWO), &passwordWO)...)

	var passwordHashWO types.String
	diags.Append(config.GetAttribute(ctx, path.Root(consts.FieldPasswordHashWO), &passwordHashWO)...)

	return passwordWO, passwordHashWO, diags
}

// upsertUser validates credentials, writes the user, applies compatibility endpoint updates, and refreshes state data.
func (r *UserpassAuthUserResource) upsertUser(ctx context.Context, data *UserpassAuthUserModel, config tfsdk.Config, writeErr func(error) (string, string)) diag.Diagnostics {
	passwordWO, passwordHashWO, diags := r.readCredentialsFromConfig(ctx, config)
	if diags.HasError() {
		return diags
	}

	diags.Append(r.validatePasswordHashVersion(passwordHashWO)...)
	if diags.HasError() {
		return diags
	}

	vaultClient, clientDiags := r.getVaultClient(ctx, data.Namespace)
	diags.Append(clientDiags...)
	if diags.HasError() {
		return diags
	}

	vaultRequest, apiDiags := r.getAPIModel(ctx, data, passwordWO.ValueString(), passwordHashWO.ValueString())
	diags.Append(apiDiags...)
	if diags.HasError() {
		return diags
	}

	_, err := vaultClient.Logical().WriteWithContext(ctx, r.userPath(data.Mount.ValueString(), data.Username.ValueString()), vaultRequest)
	if err != nil {
		diags.AddError(writeErr(err))
		return diags
	}

	if err := r.updatePasswordAndPoliciesEndpoints(ctx, vaultClient, data, passwordWO.ValueString()); err != nil {
		diags.AddError(writeErr(err))
		return diags
	}

	diags.Append(r.readAndPopulate(ctx, vaultClient, data)...)
	return diags
}

// getVaultClient returns a namespace-scoped Vault client for the resource operation.
func (r *UserpassAuthUserResource) getVaultClient(ctx context.Context, namespace types.String) (*api.Client, diag.Diagnostics) {
	vaultClient, err := client.GetClient(ctx, r.Meta(), namespace.ValueString())
	if err != nil {
		return nil, diag.Diagnostics{diag.NewErrorDiagnostic(errutil.ClientConfigureErr(err))}
	}

	return vaultClient, nil
}

// readUser reads a Userpass user from Vault and returns nil if it does not exist.
func (r *UserpassAuthUserResource) readUser(ctx context.Context, vaultClient *api.Client, data *UserpassAuthUserModel) (*api.Secret, diag.Diagnostics) {
	userResp, err := vaultClient.Logical().ReadWithContext(ctx, r.userPath(data.Mount.ValueString(), data.Username.ValueString()))
	if err != nil {
		return nil, diag.Diagnostics{diag.NewErrorDiagnostic(errutil.VaultReadErr(err))}
	}

	return userResp, nil
}

// readAndPopulate reads the user and maps the Vault response back into Terraform state model.
func (r *UserpassAuthUserResource) readAndPopulate(ctx context.Context, vaultClient *api.Client, data *UserpassAuthUserModel) diag.Diagnostics {
	userResp, diags := r.readUser(ctx, vaultClient, data)
	if diags.HasError() {
		return diags
	}
	if userResp == nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic(errutil.VaultReadResponseNil())}
	}

	return r.populateDataModelFromAPI(ctx, data, userResp)
}

// getAPIModel builds the Vault write payload from Terraform model and credential inputs.
func (r *UserpassAuthUserResource) getAPIModel(ctx context.Context, data *UserpassAuthUserModel, password, passwordHashWO string) (map[string]any, diag.Diagnostics) {
	apiModel := UserpassAuthUserAPIModel{}

	if diags := token.PopulateTokenAPIFromModel(ctx, &data.TokenModel, &apiModel.TokenAPIModel); diags.HasError() {
		return nil, diags
	}

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode Userpass user API model to map", err.Error()),
		}
	}

	if password != "" {
		vaultRequest["password"] = password
	}
	if passwordHashWO != "" {
		vaultRequest["password_hash"] = passwordHashWO
	}

	// alias_metadata requires Vault Enterprise 1.21+
	if !r.supportsAliasMetadata() {
		delete(vaultRequest, consts.FieldAliasMetadata)
	}

	return vaultRequest, nil
}

// updatePasswordAndPoliciesEndpoints writes legacy compatibility endpoints when needed.
func (r *UserpassAuthUserResource) updatePasswordAndPoliciesEndpoints(ctx context.Context, vaultClient *api.Client, data *UserpassAuthUserModel, password string) error {
	if password != "" {
		_, err := vaultClient.Logical().WriteWithContext(ctx, r.userPath(data.Mount.ValueString(), data.Username.ValueString(), "password"), map[string]any{"password": password})
		if err != nil && !util.Is404(err) {
			return fmt.Errorf("failed writing user password endpoint: %w", err)
		}
	}

	if data.TokenPolicies.IsNull() || data.TokenPolicies.IsUnknown() {
		return nil
	}

	var policies []string
	if diags := data.TokenPolicies.ElementsAs(ctx, &policies, false); diags.HasError() {
		return fmt.Errorf("failed decoding token policies for policies endpoint: %s", diags.Errors()[0].Detail())
	}

	if len(policies) == 0 {
		return nil
	}

	sort.Strings(policies)
	payload := map[string]any{
		"policies": strings.Join(policies, ","),
	}

	_, err := vaultClient.Logical().WriteWithContext(ctx, r.userPath(data.Mount.ValueString(), data.Username.ValueString(), "policies"), payload)
	if err != nil && !util.Is404(err) {
		return fmt.Errorf("failed writing user policies endpoint: %w", err)
	}

	return nil
}

// populateDataModelFromAPI maps a Vault read response into the Terraform state model.
func (r *UserpassAuthUserResource) populateDataModelFromAPI(ctx context.Context, data *UserpassAuthUserModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp UserpassAuthUserAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}

	// Save the current alias_metadata value before PopulateTokenModelFromAPI
	// overwrites it. On Vault versions prior to 1.21, the CF auth plugin does
	// not support alias_metadata: it is silently dropped on write and absent
	// on read. Restoring the value preserves plan/state consistency and avoids
	// a "provider produced inconsistent result" error.
	savedAliasMetadata := data.TokenModel.AliasMetadata

	if diags := token.PopulateTokenModelFromAPI(ctx, &data.TokenModel, &readResp.TokenAPIModel); diags.HasError() {
		return diags
	}

	if !r.supportsAliasMetadata() {
		data.TokenModel.AliasMetadata = savedAliasMetadata
	}
	//data.Mount = types.StringValue(data.Mount.ValueString())
	//data.Username = types.StringValue(data.Username.ValueString())

	return nil
}

// validatePasswordHashVersion gates password_hash usage on supported Vault version.
func (r *UserpassAuthUserResource) validatePasswordHashVersion(passwordHashWO types.String) diag.Diagnostics {
	if passwordHashWO.IsNull() || passwordHashWO.IsUnknown() || passwordHashWO.ValueString() == "" {
		return nil
	}

	if r.Meta() == nil || !r.Meta().IsAPISupported(provider.VaultVersion117) {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"Vault version unsupported",
				fmt.Sprintf("%q requires Vault 1.17 or later.", consts.FieldPasswordHashWO),
			),
		}
	}

	return nil
}

// extractUserpassUserIdentifiers parses import IDs in auth/<mount>/users/<username> format.
func extractUserpassUserIdentifiers(id string) (string, string, error) {
	if id == "" {
		return "", "", fmt.Errorf("import identifier cannot be empty")
	}

	id = strings.Trim(id, "/")
	if !userRegexp.MatchString(id) {
		return "", "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/users/<username>', namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	matches := userRegexp.FindStringSubmatch(id)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("unexpected import identifier format")
	}

	return matches[1], matches[2], nil
}
