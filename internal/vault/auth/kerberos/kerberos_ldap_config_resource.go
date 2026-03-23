// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/token"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var ldapConfigPathRegexp = regexp.MustCompile("^auth/(.+)/config/ldap$")

var (
	_ resource.Resource                = (*kerberosAuthBackendLDAPConfigResource)(nil)
	_ resource.ResourceWithConfigure   = (*kerberosAuthBackendLDAPConfigResource)(nil)
	_ resource.ResourceWithImportState = (*kerberosAuthBackendLDAPConfigResource)(nil)
)

// NewKerberosAuthBackendLDAPConfigResource is the constructor function
var NewKerberosAuthBackendLDAPConfigResource = func() resource.Resource {
	return &kerberosAuthBackendLDAPConfigResource{}
}

type kerberosAuthBackendLDAPConfigResource struct {
	base.ResourceWithConfigure
}

type kerberosAuthBackendLDAPConfigModel struct {
	token.TokenModel

	Mount                     types.String `tfsdk:"mount"`
	URL                       types.String `tfsdk:"url"`
	BindDN                    types.String `tfsdk:"binddn"`
	BindPassWO                types.String `tfsdk:"bindpass_wo"`
	BindPassWOVersion         types.Int64  `tfsdk:"bindpass_wo_version"`
	UserDN                    types.String `tfsdk:"userdn"`
	UserAttr                  types.String `tfsdk:"userattr"`
	UserFilter                types.String `tfsdk:"userfilter"`
	GroupDN                   types.String `tfsdk:"groupdn"`
	GroupFilter               types.String `tfsdk:"groupfilter"`
	GroupAttr                 types.String `tfsdk:"groupattr"`
	AnonymousGroupSearch      types.Bool   `tfsdk:"anonymous_group_search"`
	UseTokenGroups            types.Bool   `tfsdk:"use_token_groups"`
	CaseSensitiveNames        types.Bool   `tfsdk:"case_sensitive_names"`
	StartTLS                  types.Bool   `tfsdk:"starttls"`
	InsecureTLS               types.Bool   `tfsdk:"insecure_tls"`
	TLSMinVersion             types.String `tfsdk:"tls_min_version"`
	TLSMaxVersion             types.String `tfsdk:"tls_max_version"`
	Certificate               types.String `tfsdk:"certificate"`
	ClientTLSCertWO           types.String `tfsdk:"client_tls_cert_wo"`
	ClientTLSCertWOVersion    types.Int64  `tfsdk:"client_tls_cert_wo_version"`
	ClientTLSKeyWO            types.String `tfsdk:"client_tls_key_wo"`
	ClientTLSKeyWOVersion     types.Int64  `tfsdk:"client_tls_key_wo_version"`
	DiscoverDN                types.Bool   `tfsdk:"discoverdn"`
	DenyNullBind              types.Bool   `tfsdk:"deny_null_bind"`
	UPNDomain                 types.String `tfsdk:"upndomain"`
	RequestTimeout            types.Int64  `tfsdk:"request_timeout"`
	ConnectionTimeout         types.Int64  `tfsdk:"connection_timeout"`
	UsernameAsAlias           types.Bool   `tfsdk:"username_as_alias"`
	DereferenceAliases        types.String `tfsdk:"dereference_aliases"`
	MaxPageSize               types.Int64  `tfsdk:"max_page_size"`
	EnableSAMAccountNameLogin types.Bool   `tfsdk:"enable_samaccountname_login"`
}

type kerberosAuthBackendLDAPConfigAPIModel struct {
	token.TokenAPIModel `mapstructure:",squash"`

	URL                       string `json:"url" mapstructure:"url"`
	BindDN                    string `json:"binddn" mapstructure:"binddn"`
	BindPass                  string `json:"bindpass" mapstructure:"bindpass"`
	UserDN                    string `json:"userdn" mapstructure:"userdn"`
	UserAttr                  string `json:"userattr" mapstructure:"userattr"`
	UserFilter                string `json:"userfilter" mapstructure:"userfilter"`
	GroupDN                   string `json:"groupdn" mapstructure:"groupdn"`
	GroupFilter               string `json:"groupfilter" mapstructure:"groupfilter"`
	GroupAttr                 string `json:"groupattr" mapstructure:"groupattr"`
	AnonymousGroupSearch      bool   `json:"anonymous_group_search" mapstructure:"anonymous_group_search"`
	UseTokenGroups            bool   `json:"use_token_groups" mapstructure:"use_token_groups"`
	CaseSensitiveNames        bool   `json:"case_sensitive_names" mapstructure:"case_sensitive_names"`
	StartTLS                  bool   `json:"starttls" mapstructure:"starttls"`
	InsecureTLS               bool   `json:"insecure_tls" mapstructure:"insecure_tls"`
	TLSMinVersion             string `json:"tls_min_version" mapstructure:"tls_min_version"`
	TLSMaxVersion             string `json:"tls_max_version" mapstructure:"tls_max_version"`
	Certificate               string `json:"certificate" mapstructure:"certificate"`
	ClientTLSCert             string `json:"client_tls_cert" mapstructure:"client_tls_cert"`
	ClientTLSKey              string `json:"client_tls_key" mapstructure:"client_tls_key"`
	DiscoverDN                bool   `json:"discoverdn" mapstructure:"discoverdn"`
	DenyNullBind              bool   `json:"deny_null_bind" mapstructure:"deny_null_bind"`
	UPNDomain                 string `json:"upndomain" mapstructure:"upndomain"`
	RequestTimeout            int64  `json:"request_timeout" mapstructure:"request_timeout"`
	ConnectionTimeout         int64  `json:"connection_timeout" mapstructure:"connection_timeout"`
	UsernameAsAlias           bool   `json:"username_as_alias" mapstructure:"username_as_alias"`
	DereferenceAliases        string `json:"dereference_aliases" mapstructure:"dereference_aliases"`
	MaxPageSize               int64  `json:"max_page_size" mapstructure:"max_page_size"`
	EnableSAMAccountNameLogin bool   `json:"enable_samaccountname_login" mapstructure:"enable_samaccountname_login"`
}

func (r *kerberosAuthBackendLDAPConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kerberos_auth_backend_ldap_config"
}

func (r *kerberosAuthBackendLDAPConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages LDAP configuration for the Kerberos authentication method in Vault.\n\n" +
			"**Note:** Vault does not support deleting auth backend LDAP configurations via the API. " +
			"When this resource is destroyed or replaced (e.g., when changing the `mount`), " +
			"it is only removed from Terraform state. The configuration remains in Vault until " +
			"the auth mount itself is deleted.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Required:    true,
				Description: "Path where the Kerberos auth method is mounted.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldURL: schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("ldap://127.0.0.1"),
				Description: "LDAP URL to connect. Multiple URLs can be specified by concatenating them with commas. " +
					"Default: ldap://127.0.0.1",
			},
			consts.FieldBindDN: schema.StringAttribute{
				Optional:    true,
				Description: "Distinguished name of object to bind for search (e.g., 'cn=vault,ou=Users,dc=example,dc=com').",
			},
			consts.FieldBindPassWO: schema.StringAttribute{
				Optional:    true,
				WriteOnly:   true,
				Sensitive:   true,
				Description: "LDAP password for searching for the user DN (write-only). Must be used together with bindpass_wo_version.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(consts.FieldBindPassWOVersion)),
				},
			},
			consts.FieldBindPassWOVersion: schema.Int64Attribute{
				Optional:    true,
				Description: "Version identifier for bindpass updates. Change to trigger password update. Must be used together with bindpass_wo.",
				Validators: []validator.Int64{
					int64validator.AlsoRequires(path.MatchRoot(consts.FieldBindPassWO)),
				},
			},
			consts.FieldUserDN: schema.StringAttribute{
				Optional:    true,
				Description: "LDAP domain to use for users (e.g., ou=People,dc=example,dc=org).",
			},
			consts.FieldUserAttr: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("cn"),
				Description: "Attribute used as username. Common values: 'samaccountname', 'uid'. Default: 'cn'",
			},
			consts.FieldUserFilter: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("({{.UserAttr}}={{.Username}})"),
				Description: "Go template for LDAP user search filter. Default: '({{.UserAttr}}={{.Username}})'",
			},
			consts.FieldGroupDN: schema.StringAttribute{
				Optional:    true,
				Description: "LDAP search base to use for group membership search (e.g., ou=Groups,dc=example,dc=org).",
			},
			consts.FieldGroupFilter: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))"),
				Description: "Go template for querying group membership of user. Default: '(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))'",
			},
			consts.FieldGroupAttr: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("cn"),
				Description: "LDAP attribute to follow for group membership. Default: 'cn'",
			},
			consts.FieldAnonymousGroupSearch: schema.BoolAttribute{
				Optional:    true,
				Description: "Use anonymous binds when performing LDAP group searches. Default: false.",
			},
			consts.FieldUseTokenGroups: schema.BoolAttribute{
				Optional:    true,
				Description: "If true, use the Active Directory tokenGroups constructed attribute. Default: false.",
			},
			consts.FieldCaseSensitiveNames: schema.BoolAttribute{
				Optional:    true,
				Description: "If true, usernames and group names are case sensitive. Default: false.",
			},
			consts.FieldStartTLS: schema.BoolAttribute{
				Optional:    true,
				Description: "Issue a StartTLS command after establishing an unencrypted connection. Default: false.",
			},
			consts.FieldInsecureTLS: schema.BoolAttribute{
				Optional:    true,
				Description: "Skip TLS certificate verification. Not recommended for production. Default: false.",
			},
			consts.FieldTLSMinVersion: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("tls12"),
				Description: "Minimum TLS version to use. Accepted values are 'tls10', 'tls11', 'tls12' or 'tls13'. Default: 'tls12'.",
			},
			consts.FieldTLSMaxVersion: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("tls12"),
				Description: "Maximum TLS version to use. Accepted values are 'tls10', 'tls11', 'tls12' or 'tls13'. Default: 'tls12'.",
			},
			consts.FieldCertificate: schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded.",
			},
			consts.FieldClientTLSCertWO: schema.StringAttribute{
				Optional:    true,
				WriteOnly:   true,
				Sensitive:   true,
				Description: "Client certificate to provide to the LDAP server, must be x509 PEM encoded (write-only). Must be used together with client_tls_cert_wo_version.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(consts.FieldClientTLSCertWOVersion)),
				},
			},
			consts.FieldClientTLSCertWOVersion: schema.Int64Attribute{
				Optional:    true,
				Description: "Version identifier for client TLS certificate updates. Change to trigger certificate update. Must be used together with client_tls_cert_wo.",
				Validators: []validator.Int64{
					int64validator.AlsoRequires(path.MatchRoot(consts.FieldClientTLSCertWO)),
				},
			},
			consts.FieldClientTLSKeyWO: schema.StringAttribute{
				Optional:    true,
				WriteOnly:   true,
				Sensitive:   true,
				Description: "Client certificate key to provide to the LDAP server, must be x509 PEM encoded (write-only). Must be used together with client_tls_key_wo_version.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(consts.FieldClientTLSKeyWOVersion)),
				},
			},
			consts.FieldClientTLSKeyWOVersion: schema.Int64Attribute{
				Optional:    true,
				Description: "Version identifier for client TLS key updates. Must be used together with client_tls_key_wo.",
				Validators: []validator.Int64{
					int64validator.AlsoRequires(path.MatchRoot(consts.FieldClientTLSKeyWO)),
				},
			},
			consts.FieldDiscoverDN: schema.BoolAttribute{
				Optional:    true,
				Description: "Use anonymous bind to discover bind DN of a user. Default: false.",
			},
			consts.FieldDenyNullBind: schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Denies an unauthenticated LDAP bind request if the user's password is empty. Default: true.",
			},
			consts.FieldUPNDomain: schema.StringAttribute{
				Optional:    true,
				Description: "Enables userPrincipalDomain login with [username]@UPNDomain.",
			},
			consts.FieldRequestTimeout: schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(90),
				Description: "Timeout, in seconds, for the connection when making requests against the server. Default: 90.",
			},
			consts.FieldConnectionTimeout: schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(30),
				Description: "Timeout, in seconds, when attempting to connect to the LDAP server. Default: 30.",
			},
			consts.FieldUsernameAsAlias: schema.BoolAttribute{
				Optional:    true,
				Description: "Use username as alias name. Default: false.",
			},
			consts.FieldDereferenceAliases: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("never"),
				Description: "When aliases should be dereferenced on search operations. Accepted values are 'never', 'finding', 'searching', 'always'. Default: 'never'",
			},
			consts.FieldMaxPageSize: schema.Int64Attribute{
				Optional:    true,
				Description: "If set to a value greater than 0, the LDAP backend will use the LDAP server's paged search control. Default: 0.",
			},
			consts.FieldEnableSamaccountnameLogin: schema.BoolAttribute{
				Optional:    true,
				Description: "If true, matching sAMAccountName attribute values will be allowed to login when upndomain is defined. Default: false. **Note:** This field is only supported in Vault 1.19.0 and above. Do not configure this attribute if your Vault version is below 1.19.0.",
			},
		},
	}

	// Add token schema fields
	token.MustAddBaseAndTokenSchemas(&resp.Schema)
}

func (r *kerberosAuthBackendLDAPConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan kerberosAuthBackendLDAPConfigModel
	var config kerberosAuthBackendLDAPConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeConfig(ctx, &plan, &config, nil)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *kerberosAuthBackendLDAPConfigResource) writeConfig(ctx context.Context, plan *kerberosAuthBackendLDAPConfigModel, config *kerberosAuthBackendLDAPConfigModel, state *kerberosAuthBackendLDAPConfigModel) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return diags
	}

	mount := strings.Trim(plan.Mount.ValueString(), "/")
	configPath := r.configPath(mount)

	// Build the API request
	vaultRequest, apiDiags := r.getApiModel(ctx, plan, config, state)
	diags.Append(apiDiags...)
	if diags.HasError() {
		return diags
	}

	// Write config to Vault
	tflog.Debug(ctx, fmt.Sprintf("Writing Kerberos LDAP config to '%s'", configPath))
	_, err = vaultClient.Logical().WriteWithContext(ctx, configPath, vaultRequest)
	if err != nil {
		diags.AddError(
			"Error writing Kerberos LDAP config",
			fmt.Sprintf("Could not write Kerberos LDAP config to '%s': %s", configPath, err),
		)
		return diags
	}
	tflog.Info(ctx, fmt.Sprintf("Kerberos LDAP config successfully written to '%s'", configPath))

	// Read back the configuration
	found, readDiags := r.read(ctx, plan)
	diags.Append(readDiags...)
	if diags.HasError() {
		return diags
	}
	if !found {
		diags.AddError(
			"Error reading back Kerberos LDAP config after write",
			fmt.Sprintf("Config at '%s' was not found after successful write", r.configPath(strings.Trim(plan.Mount.ValueString(), "/"))),
		)
		return diags
	}

	return diags
}

// getApiModel builds the Vault API request map from the Terraform data model.
func (r *kerberosAuthBackendLDAPConfigResource) getApiModel(ctx context.Context, plan *kerberosAuthBackendLDAPConfigModel, config *kerberosAuthBackendLDAPConfigModel, state *kerberosAuthBackendLDAPConfigModel) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Build API model
	apiModel := kerberosAuthBackendLDAPConfigAPIModel{
		URL:                       plan.URL.ValueString(),
		UserAttr:                  plan.UserAttr.ValueString(),
		UserFilter:                plan.UserFilter.ValueString(),
		GroupFilter:               plan.GroupFilter.ValueString(),
		GroupAttr:                 plan.GroupAttr.ValueString(),
		AnonymousGroupSearch:      plan.AnonymousGroupSearch.ValueBool(),
		UseTokenGroups:            plan.UseTokenGroups.ValueBool(),
		CaseSensitiveNames:        plan.CaseSensitiveNames.ValueBool(),
		StartTLS:                  plan.StartTLS.ValueBool(),
		InsecureTLS:               plan.InsecureTLS.ValueBool(),
		TLSMinVersion:             plan.TLSMinVersion.ValueString(),
		TLSMaxVersion:             plan.TLSMaxVersion.ValueString(),
		DiscoverDN:                plan.DiscoverDN.ValueBool(),
		DenyNullBind:              plan.DenyNullBind.ValueBool(),
		RequestTimeout:            plan.RequestTimeout.ValueInt64(),
		ConnectionTimeout:         plan.ConnectionTimeout.ValueInt64(),
		UsernameAsAlias:           plan.UsernameAsAlias.ValueBool(),
		DereferenceAliases:        plan.DereferenceAliases.ValueString(),
		MaxPageSize:               plan.MaxPageSize.ValueInt64(),
		EnableSAMAccountNameLogin: plan.EnableSAMAccountNameLogin.ValueBool(),
	}

	if !plan.BindDN.IsNull() {
		apiModel.BindDN = plan.BindDN.ValueString()
	}

	if !config.BindPassWO.IsNull() {
		if state == nil || !plan.BindPassWOVersion.Equal(state.BindPassWOVersion) {
			apiModel.BindPass = config.BindPassWO.ValueString()
			tflog.Debug(ctx, "Bindpass version changed or new resource, updating bindpass")
		}
	}

	if !plan.UserDN.IsNull() {
		apiModel.UserDN = plan.UserDN.ValueString()
	}

	if !plan.GroupDN.IsNull() {
		apiModel.GroupDN = plan.GroupDN.ValueString()
	}

	if !plan.Certificate.IsNull() {
		apiModel.Certificate = plan.Certificate.ValueString()
	}

	if !config.ClientTLSCertWO.IsNull() {
		if state == nil || !plan.ClientTLSCertWOVersion.Equal(state.ClientTLSCertWOVersion) {
			apiModel.ClientTLSCert = config.ClientTLSCertWO.ValueString()
			tflog.Debug(ctx, "Client TLS cert version changed or new resource, updating client_tls_cert")
		}
	}

	if !config.ClientTLSKeyWO.IsNull() {
		if state == nil || !plan.ClientTLSKeyWOVersion.Equal(state.ClientTLSKeyWOVersion) {
			apiModel.ClientTLSKey = config.ClientTLSKeyWO.ValueString()
			tflog.Debug(ctx, "Client TLS key version changed or new resource, updating client_tls_key")
		}
	}

	if !plan.UPNDomain.IsNull() {
		apiModel.UPNDomain = plan.UPNDomain.ValueString()
	}

	// Populate token fields
	diags.Append(token.PopulateTokenAPIFromModel(ctx, &plan.TokenModel, &apiModel.TokenAPIModel)...)
	if diags.HasError() {
		return nil, diags
	}

	// Convert API model to map for Vault request
	var data map[string]interface{}
	if err := mapstructure.Decode(apiModel, &data); err != nil {
		diags.AddError("Failed to encode LDAP config API model", err.Error())
		return nil, diags
	}

	if r.Meta() == nil || !r.Meta().IsAPISupported(provider.VaultVersion121) {
		delete(data, consts.FieldAliasMetadata)
	}

	if r.Meta() == nil || !r.Meta().IsAPISupported(provider.VaultVersion119) {
		delete(data, consts.FieldEnableSamaccountnameLogin)
	}

	return data, diags
}

func (r *kerberosAuthBackendLDAPConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state kerberosAuthBackendLDAPConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read config from Vault
	found, readDiags := r.read(ctx, &state)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If not found, remove from state
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// read is a reusable helper that reads configuration from Vault.
// Returns true if the config was found, false if not found.
// Used by the Read operation.
func (r *kerberosAuthBackendLDAPConfigResource) read(ctx context.Context, data *kerberosAuthBackendLDAPConfigModel) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return false, diags
	}

	mount := strings.Trim(data.Mount.ValueString(), "/")
	configPath := r.configPath(mount)

	tflog.Debug(ctx, fmt.Sprintf("Reading Kerberos LDAP config from '%s'", configPath))
	resp, err := vaultClient.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return false, diags
	}

	if resp == nil {
		tflog.Warn(ctx, fmt.Sprintf("Kerberos LDAP config at '%s' not found, removing from state", configPath))
		return false, diags
	}

	// Populate model from API response
	populateDiags := r.populateDataModelFromApi(ctx, data, resp.Data)
	diags.Append(populateDiags...)
	return true, diags
}

// populateDataModelFromApi maps the Vault API response to the Terraform data model.
func (r *kerberosAuthBackendLDAPConfigResource) populateDataModelFromApi(ctx context.Context, tfModel *kerberosAuthBackendLDAPConfigModel, respData map[string]interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	if respData == nil {
		diags.AddError("Missing data in API response", "The API response data was nil.")
		return diags
	}

	// Decode response into API model
	var apiModel kerberosAuthBackendLDAPConfigAPIModel
	if err := model.ToAPIModel(respData, &apiModel); err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return diags
	}

	// Set unconditional string fields
	tfModel.URL = types.StringValue(apiModel.URL)
	tfModel.UserAttr = types.StringValue(apiModel.UserAttr)
	tfModel.UserFilter = types.StringValue(apiModel.UserFilter)
	tfModel.GroupFilter = types.StringValue(apiModel.GroupFilter)
	tfModel.GroupAttr = types.StringValue(apiModel.GroupAttr)
	tfModel.TLSMinVersion = types.StringValue(apiModel.TLSMinVersion)
	tfModel.TLSMaxVersion = types.StringValue(apiModel.TLSMaxVersion)
	tfModel.DereferenceAliases = types.StringValue(apiModel.DereferenceAliases)
	tfModel.DenyNullBind = types.BoolValue(apiModel.DenyNullBind)
	tfModel.RequestTimeout = types.Int64Value(apiModel.RequestTimeout)
	tfModel.ConnectionTimeout = types.Int64Value(apiModel.ConnectionTimeout)

	// Set conditional string fields (nullable)
	if apiModel.BindDN != "" {
		tfModel.BindDN = types.StringValue(apiModel.BindDN)
	} else {
		tfModel.BindDN = types.StringNull()
	}

	if apiModel.UserDN != "" {
		tfModel.UserDN = types.StringValue(apiModel.UserDN)
	} else {
		tfModel.UserDN = types.StringNull()
	}

	if apiModel.GroupDN != "" {
		tfModel.GroupDN = types.StringValue(apiModel.GroupDN)
	} else {
		tfModel.GroupDN = types.StringNull()
	}

	if apiModel.Certificate != "" {
		tfModel.Certificate = types.StringValue(apiModel.Certificate)
	} else {
		tfModel.Certificate = types.StringNull()
	}

	if apiModel.UPNDomain != "" {
		tfModel.UPNDomain = types.StringValue(apiModel.UPNDomain)
	} else {
		tfModel.UPNDomain = types.StringNull()
	}

	if apiModel.AnonymousGroupSearch {
		tfModel.AnonymousGroupSearch = types.BoolValue(apiModel.AnonymousGroupSearch)
	}

	if apiModel.UseTokenGroups {
		tfModel.UseTokenGroups = types.BoolValue(apiModel.UseTokenGroups)
	}

	if apiModel.CaseSensitiveNames {
		tfModel.CaseSensitiveNames = types.BoolValue(apiModel.CaseSensitiveNames)
	}

	if apiModel.StartTLS {
		tfModel.StartTLS = types.BoolValue(apiModel.StartTLS)
	}

	if apiModel.InsecureTLS {
		tfModel.InsecureTLS = types.BoolValue(apiModel.InsecureTLS)
	}

	if apiModel.DiscoverDN {
		tfModel.DiscoverDN = types.BoolValue(apiModel.DiscoverDN)
	}

	if apiModel.UsernameAsAlias {
		tfModel.UsernameAsAlias = types.BoolValue(apiModel.UsernameAsAlias)
	}

	if apiModel.MaxPageSize != 0 {
		tfModel.MaxPageSize = types.Int64Value(apiModel.MaxPageSize)
	} else {
		tfModel.MaxPageSize = types.Int64Null()
	}

	if apiModel.EnableSAMAccountNameLogin {
		tfModel.EnableSAMAccountNameLogin = types.BoolValue(apiModel.EnableSAMAccountNameLogin)
	}

	// Populate token fields using the token package helper
	diags.Append(token.PopulateTokenModelFromAPI(ctx, &tfModel.TokenModel, &apiModel.TokenAPIModel)...)

	return diags
}

func (r *kerberosAuthBackendLDAPConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan kerberosAuthBackendLDAPConfigModel
	var state kerberosAuthBackendLDAPConfigModel
	var config kerberosAuthBackendLDAPConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeConfig(ctx, &plan, &config, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *kerberosAuthBackendLDAPConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state kerberosAuthBackendLDAPConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mount := strings.Trim(state.Mount.ValueString(), "/")
	configPath := r.configPath(mount)

	// Configuration endpoints cannot be deleted from Vault, only the auth mount itself can be deleted.
	// This function only removes the resource from Terraform state.
	tflog.Debug(ctx, "Removing Kerberos LDAP config from Terraform state")

	resp.Diagnostics.AddWarning(
		"Configuration Remains in Vault",
		fmt.Sprintf("The Kerberos LDAP configuration at '%s' has been removed from Terraform state, "+
			"but it may still exist in Vault unless the auth mount itself is deleted.", configPath),
	)
}

// ImportState handles resource import
func (r *kerberosAuthBackendLDAPConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	var mount string
	var err error

	// Parse the import ID using the official Vault API format
	mount, err = r.mountFromPath(id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID format",
			fmt.Sprintf("Expected format: 'auth/<mount>/config/ldap', got: '%s'", req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)

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

// configPath returns the Vault API path for Kerberos LDAP config
func (r *kerberosAuthBackendLDAPConfigResource) configPath(mount string) string {
	return fmt.Sprintf("auth/%s/config/ldap", mount)
}

// mountFromPath extracts the mount from the full path
func (r *kerberosAuthBackendLDAPConfigResource) mountFromPath(path string) (string, error) {
	if !ldapConfigPathRegexp.MatchString(path) {
		return "", fmt.Errorf("no mount found in path: %s", path)
	}
	matches := ldapConfigPathRegexp.FindStringSubmatch(path)
	if len(matches) != 2 {
		return "", fmt.Errorf("unexpected number of matches in path: %s", path)
	}
	return matches[1], nil
}
