// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/token"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldURL                       = consts.FieldURL
	fieldAliasMetadata             = consts.FieldAliasMetadata
	fieldBindDN                    = consts.FieldBindDN
	fieldBindPassWO                = consts.FieldBindPassWO
	fieldBindPassWOVersion         = consts.FieldBindPassWOVersion
	fieldUserDN                    = consts.FieldUserDN
	fieldUserAttr                  = consts.FieldUserAttr
	fieldUserFilter                = consts.FieldUserFilter
	fieldGroupDN                   = consts.FieldGroupDN
	fieldGroupFilter               = consts.FieldGroupFilter
	fieldGroupAttr                 = consts.FieldGroupAttr
	fieldAnonymousGroupSearch      = consts.FieldAnonymousGroupSearch
	fieldUseTokenGroups            = consts.FieldUseTokenGroups
	fieldCaseSensitiveNames        = consts.FieldCaseSensitiveNames
	fieldStartTLS                  = consts.FieldStartTLS
	fieldInsecureTLS               = consts.FieldInsecureTLS
	fieldTLSMinVersion             = consts.FieldTLSMinVersion
	fieldTLSMaxVersion             = consts.FieldTLSMaxVersion
	fieldCertificate               = consts.FieldCertificate
	fieldClientTLSCertWO           = consts.FieldClientTLSCertWO
	fieldClientTLSCertWOVersion    = consts.FieldClientTLSCertWOVersion
	fieldClientTLSKeyWO            = consts.FieldClientTLSKeyWO
	fieldClientTLSKeyWOVersion     = consts.FieldClientTLSKeyWOVersion
	fieldDiscoverDN                = consts.FieldDiscoverDN
	fieldDenyNullBind              = consts.FieldDenyNullBind
	fieldUPNDomain                 = consts.FieldUPNDomain
	fieldRequestTimeout            = consts.FieldRequestTimeout
	fieldConnectionTimeout         = consts.FieldConnectionTimeout
	fieldUsernameAsAlias           = consts.FieldUsernameAsAlias
	fieldDereferenceAliases        = consts.FieldDereferenceAliases
	fieldMaxPageSize               = consts.FieldMaxPageSize
	fieldEnableSAMAccountNameLogin = consts.FieldEnableSamaccountnameLogin
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
	BindPassWOVersion         types.String `tfsdk:"bindpass_wo_version"`
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
	ClientTLSCertWOVersion    types.String `tfsdk:"client_tls_cert_wo_version"`
	ClientTLSKeyWO            types.String `tfsdk:"client_tls_key_wo"`
	ClientTLSKeyWOVersion     types.String `tfsdk:"client_tls_key_wo_version"`
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

	URL                       string `json:"url,omitempty" mapstructure:"url,omitempty"`
	BindDN                    string `json:"binddn" mapstructure:"binddn"`
	BindPass                  string `json:"bindpass,omitempty" mapstructure:"bindpass,omitempty"`
	UserDN                    string `json:"userdn" mapstructure:"userdn"`
	UserAttr                  string `json:"userattr,omitempty" mapstructure:"userattr,omitempty"`
	UserFilter                string `json:"userfilter,omitempty" mapstructure:"userfilter,omitempty"`
	GroupDN                   string `json:"groupdn" mapstructure:"groupdn"`
	GroupFilter               string `json:"groupfilter,omitempty" mapstructure:"groupfilter,omitempty"`
	GroupAttr                 string `json:"groupattr,omitempty" mapstructure:"groupattr,omitempty"`
	AnonymousGroupSearch      bool   `json:"anonymous_group_search" mapstructure:"anonymous_group_search"`
	UseTokenGroups            bool   `json:"use_token_groups" mapstructure:"use_token_groups"`
	CaseSensitiveNames        bool   `json:"case_sensitive_names" mapstructure:"case_sensitive_names"`
	StartTLS                  bool   `json:"starttls" mapstructure:"starttls"`
	InsecureTLS               bool   `json:"insecure_tls" mapstructure:"insecure_tls"`
	TLSMinVersion             string `json:"tls_min_version,omitempty" mapstructure:"tls_min_version,omitempty"`
	TLSMaxVersion             string `json:"tls_max_version,omitempty" mapstructure:"tls_max_version,omitempty"`
	Certificate               string `json:"certificate" mapstructure:"certificate"`
	ClientTLSCert             string `json:"client_tls_cert,omitempty" mapstructure:"client_tls_cert,omitempty"`
	ClientTLSKey              string `json:"client_tls_key,omitempty" mapstructure:"client_tls_key,omitempty"`
	DiscoverDN                bool   `json:"discoverdn" mapstructure:"discoverdn"`
	DenyNullBind              bool   `json:"deny_null_bind" mapstructure:"deny_null_bind"`
	UPNDomain                 string `json:"upndomain" mapstructure:"upndomain"`
	RequestTimeout            int64  `json:"request_timeout,omitempty" mapstructure:"request_timeout,omitempty"`
	ConnectionTimeout         int64  `json:"connection_timeout,omitempty" mapstructure:"connection_timeout,omitempty"`
	UsernameAsAlias           bool   `json:"username_as_alias" mapstructure:"username_as_alias"`
	DereferenceAliases        string `json:"dereference_aliases,omitempty" mapstructure:"dereference_aliases,omitempty"`
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
			fieldMount: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("kerberos"),
				Description: "Path where the Kerberos auth method is mounted.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					validators.PathValidator(),
				},
			},
			fieldURL: schema.StringAttribute{
				Optional: true,
				Description: "LDAP URL to connect. Multiple URLs can be specified by concatenating them with commas. " +
					"Default: ldap://127.0.0.1",
			},
			fieldBindDN: schema.StringAttribute{
				Optional:    true,
				Description: "Distinguished name of object to bind for search (e.g., 'cn=vault,ou=Users,dc=example,dc=com').",
			},
			fieldBindPassWO: schema.StringAttribute{
				Optional:    true,
				WriteOnly:   true,
				Description: "LDAP password for searching for the user DN (write-only). Must be used together with bindpass_wo_version.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(fieldBindPassWOVersion)),
				},
			},
			fieldBindPassWOVersion: schema.StringAttribute{
				Optional:    true,
				Description: "Version identifier for bindpass updates. Change to trigger password update. Must be used together with bindpass_wo.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(fieldBindPassWO)),
				},
			},
			fieldUserDN: schema.StringAttribute{
				Optional:    true,
				Description: "LDAP domain to use for users (e.g., ou=People,dc=example,dc=org).",
			},
			fieldUserAttr: schema.StringAttribute{
				Optional:    true,
				Description: "Attribute used as username. Common values: 'samaccountname', 'uid'. Default: 'cn'",
			},
			fieldUserFilter: schema.StringAttribute{
				Optional:    true,
				Description: "Go template for LDAP user search filter. Default: '({{.UserAttr}}={{.Username}})'",
			},
			fieldGroupDN: schema.StringAttribute{
				Optional:    true,
				Description: "LDAP search base to use for group membership search (e.g., ou=Groups,dc=example,dc=org).",
			},
			fieldGroupFilter: schema.StringAttribute{
				Optional:    true,
				Description: "Go template for querying group membership of user. Default: '(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))'",
			},
			fieldGroupAttr: schema.StringAttribute{
				Optional:    true,
				Description: "LDAP attribute to follow for group membership. Default: 'cn'",
			},
			fieldAnonymousGroupSearch: schema.BoolAttribute{
				Optional:    true,
				Description: "Use anonymous binds when performing LDAP group searches. Default: false.",
			},
			fieldUseTokenGroups: schema.BoolAttribute{
				Optional:    true,
				Description: "If true, use the Active Directory tokenGroups constructed attribute. Default: false.",
			},
			fieldCaseSensitiveNames: schema.BoolAttribute{
				Optional:    true,
				Description: "If true, usernames and group names are case sensitive. Default: false.",
			},
			fieldStartTLS: schema.BoolAttribute{
				Optional:    true,
				Description: "Issue a StartTLS command after establishing an unencrypted connection. Default: false.",
			},
			fieldInsecureTLS: schema.BoolAttribute{
				Optional:    true,
				Description: "Skip TLS certificate verification. Not recommended for production. Default: false.",
			},
			fieldTLSMinVersion: schema.StringAttribute{
				Optional:    true,
				Description: "Minimum TLS version to use. Accepted values are 'tls10', 'tls11', 'tls12' or 'tls13'. Default: 'tls12'.",
			},
			fieldTLSMaxVersion: schema.StringAttribute{
				Optional:    true,
				Description: "Maximum TLS version to use. Accepted values are 'tls10', 'tls11', 'tls12' or 'tls13'. Default: 'tls12'.",
			},
			fieldCertificate: schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded.",
			},
			fieldClientTLSCertWO: schema.StringAttribute{
				Optional:    true,
				WriteOnly:   true,
				Description: "Client certificate to provide to the LDAP server, must be x509 PEM encoded (write-only). Must be used together with client_tls_cert_wo_version.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(fieldClientTLSCertWOVersion)),
				},
			},
			fieldClientTLSCertWOVersion: schema.StringAttribute{
				Optional:    true,
				Description: "Version identifier for client TLS certificate updates. Change to trigger certificate update. Must be used together with client_tls_cert_wo.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(fieldClientTLSCertWO)),
				},
			},
			fieldClientTLSKeyWO: schema.StringAttribute{
				Optional:    true,
				WriteOnly:   true,
				Description: "Client certificate key to provide to the LDAP server, must be x509 PEM encoded (write-only). Must be used together with client_tls_key_wo_version.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(fieldClientTLSKeyWOVersion)),
				},
			},
			fieldClientTLSKeyWOVersion: schema.StringAttribute{
				Optional:    true,
				Description: "Version identifier for client TLS key updates. Must be used together with client_tls_key_wo.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(fieldClientTLSKeyWO)),
				},
			},
			fieldDiscoverDN: schema.BoolAttribute{
				Optional:    true,
				Description: "Use anonymous bind to discover bind DN of a user. Default: false.",
			},
			fieldDenyNullBind: schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Denies an unauthenticated LDAP bind request if the user's password is empty. Default: true.",
			},
			fieldUPNDomain: schema.StringAttribute{
				Optional:    true,
				Description: "Enables userPrincipalDomain login with [username]@UPNDomain.",
			},
			fieldRequestTimeout: schema.Int64Attribute{
				Optional:    true,
				Description: "Timeout, in seconds, for the connection when making requests against the server. Default: 90.",
			},
			fieldConnectionTimeout: schema.Int64Attribute{
				Optional:    true,
				Description: "Timeout, in seconds, when attempting to connect to the LDAP server. Default: 30.",
			},
			fieldUsernameAsAlias: schema.BoolAttribute{
				Optional:    true,
				Description: "Use username as alias name. Default: false.",
			},
			fieldDereferenceAliases: schema.StringAttribute{
				Optional:    true,
				Description: "When aliases should be dereferenced on search operations. Accepted values are 'never', 'finding', 'searching', 'always'. Default: 'never'",
			},
			fieldMaxPageSize: schema.Int64Attribute{
				Optional:    true,
				Description: "If set to a value greater than 0, the LDAP backend will use the LDAP server's paged search control. Default: 0.",
			},
			fieldEnableSAMAccountNameLogin: schema.BoolAttribute{
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

	resp.Diagnostics.Append(r.writeConfig(ctx, &plan, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *kerberosAuthBackendLDAPConfigResource) writeConfig(ctx context.Context, plan *kerberosAuthBackendLDAPConfigModel, config *kerberosAuthBackendLDAPConfigModel) diag.Diagnostics {
	return r.writeConfigWithState(ctx, plan, config, nil)
}

func (r *kerberosAuthBackendLDAPConfigResource) writeConfigWithState(ctx context.Context, plan *kerberosAuthBackendLDAPConfigModel, config *kerberosAuthBackendLDAPConfigModel, state *kerberosAuthBackendLDAPConfigModel) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		diags.AddError("Error getting client", err.Error())
		return diags
	}

	mount := plan.Mount.ValueString()
	configPath := fmt.Sprintf("/auth/%s/config/ldap", mount)

	// Build API model
	apiModel := kerberosAuthBackendLDAPConfigAPIModel{}

	if !plan.URL.IsNull() {
		apiModel.URL = plan.URL.ValueString()
	}

	if !plan.BindDN.IsNull() {
		apiModel.BindDN = plan.BindDN.ValueString()
	}

	// Only send bindpass if:
	// 1. This is a create operation (state is nil), OR
	// 2. The version field has changed
	if !config.BindPassWO.IsNull() {
		if state == nil || !plan.BindPassWOVersion.Equal(state.BindPassWOVersion) {
			apiModel.BindPass = config.BindPassWO.ValueString()
			log.Printf("[DEBUG] Bindpass version changed or new resource, updating bindpass")
		}
	}

	if !plan.UserDN.IsNull() {
		apiModel.UserDN = plan.UserDN.ValueString()
	}

	if !plan.UserAttr.IsNull() {
		apiModel.UserAttr = plan.UserAttr.ValueString()
	}

	if !plan.UserFilter.IsNull() {
		apiModel.UserFilter = plan.UserFilter.ValueString()
	}

	if !plan.GroupDN.IsNull() {
		apiModel.GroupDN = plan.GroupDN.ValueString()
	}

	if !plan.GroupFilter.IsNull() {
		apiModel.GroupFilter = plan.GroupFilter.ValueString()
	}

	if !plan.GroupAttr.IsNull() {
		apiModel.GroupAttr = plan.GroupAttr.ValueString()
	}

	apiModel.AnonymousGroupSearch = plan.AnonymousGroupSearch.ValueBool()

	apiModel.UseTokenGroups = plan.UseTokenGroups.ValueBool()

	apiModel.CaseSensitiveNames = plan.CaseSensitiveNames.ValueBool()

	apiModel.StartTLS = plan.StartTLS.ValueBool()

	apiModel.InsecureTLS = plan.InsecureTLS.ValueBool()

	if !plan.TLSMinVersion.IsNull() {
		apiModel.TLSMinVersion = plan.TLSMinVersion.ValueString()
	}
	if !plan.TLSMaxVersion.IsNull() {
		apiModel.TLSMaxVersion = plan.TLSMaxVersion.ValueString()
	}
	if !plan.Certificate.IsNull() {
		apiModel.Certificate = plan.Certificate.ValueString()
	}

	// Only send client_tls_cert if:
	// 1. This is a create operation (state is nil), OR
	// 2. The version field has changed
	if !config.ClientTLSCertWO.IsNull() {
		if state == nil || !plan.ClientTLSCertWOVersion.Equal(state.ClientTLSCertWOVersion) {
			apiModel.ClientTLSCert = config.ClientTLSCertWO.ValueString()
			log.Printf("[DEBUG] Client TLS cert version changed or new resource, updating client_tls_cert")
		}
	}

	// Only send client_tls_key if:
	// 1. This is a create operation (state is nil), OR
	// 2. The version field has changed
	if !config.ClientTLSKeyWO.IsNull() {
		if state == nil || !plan.ClientTLSKeyWOVersion.Equal(state.ClientTLSKeyWOVersion) {
			apiModel.ClientTLSKey = config.ClientTLSKeyWO.ValueString()
			log.Printf("[DEBUG] Client TLS key version changed or new resource, updating client_tls_key")
		}
	}

	apiModel.DiscoverDN = plan.DiscoverDN.ValueBool()

	apiModel.DenyNullBind = plan.DenyNullBind.ValueBool()

	if !plan.UPNDomain.IsNull() {
		apiModel.UPNDomain = plan.UPNDomain.ValueString()
	}

	if !plan.RequestTimeout.IsNull() {
		apiModel.RequestTimeout = plan.RequestTimeout.ValueInt64()
	}

	if !plan.ConnectionTimeout.IsNull() {
		apiModel.ConnectionTimeout = plan.ConnectionTimeout.ValueInt64()
	}

	apiModel.UsernameAsAlias = plan.UsernameAsAlias.ValueBool()

	if !plan.DereferenceAliases.IsNull() {
		apiModel.DereferenceAliases = plan.DereferenceAliases.ValueString()
	}

	apiModel.MaxPageSize = plan.MaxPageSize.ValueInt64()

	apiModel.EnableSAMAccountNameLogin = plan.EnableSAMAccountNameLogin.ValueBool()

	// Populate token fields
	diags.Append(token.PopulateTokenAPIFromModel(ctx, &plan.TokenModel, &apiModel.TokenAPIModel)...)
	if diags.HasError() {
		return diags
	}

	// Convert API model to map for Vault request
	var data map[string]interface{}
	if err := mapstructure.Decode(apiModel, &data); err != nil {
		diags.AddError("Failed to encode LDAP config API model", err.Error())
		return diags
	}

	if r.Meta() == nil || !r.Meta().IsAPISupported(provider.VaultVersion121) {
		delete(data, fieldAliasMetadata)
	}

	if r.Meta() == nil || !r.Meta().IsAPISupported(provider.VaultVersion119) {
		delete(data, fieldEnableSAMAccountNameLogin)
	}

	log.Printf("[DEBUG] Writing Kerberos LDAP config to %q", configPath)
	_, err = vaultClient.Logical().Write(configPath, data)
	if err != nil {
		diags.AddError(
			fmt.Sprintf("Error writing Kerberos LDAP config to %q", configPath),
			err.Error(),
		)
		return diags
	}

	// Read back the configuration
	diags.Append(r.read(ctx, plan)...)

	return diags
}

func (r *kerberosAuthBackendLDAPConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state kerberosAuthBackendLDAPConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.read(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *kerberosAuthBackendLDAPConfigResource) read(ctx context.Context, tfModel *kerberosAuthBackendLDAPConfigModel) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), tfModel.Namespace.ValueString())
	if err != nil {
		diags.AddError("Error getting client", err.Error())
		return diags
	}

	mount := tfModel.Mount.ValueString()
	configPath := fmt.Sprintf("/auth/%s/config/ldap", mount)

	log.Printf("[DEBUG] Reading Kerberos LDAP config from %q", configPath)
	resp, err := vaultClient.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		diags.AddError(
			fmt.Sprintf("Error reading Kerberos LDAP config from %q", configPath),
			err.Error(),
		)
		return diags
	}

	if resp == nil {
		diags.AddError(
			"Kerberos LDAP config not found",
			fmt.Sprintf("No configuration found at %q", configPath),
		)
		return diags
	}

	// Decode response into API model
	var apiModel kerberosAuthBackendLDAPConfigAPIModel
	if err := model.ToAPIModel(resp.Data, &apiModel); err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return diags
	}

	if !tfModel.URL.IsNull() {
		tfModel.URL = types.StringValue(apiModel.URL)
	}

	if !tfModel.BindDN.IsNull() {
		tfModel.BindDN = types.StringValue(apiModel.BindDN)
	}

	if !tfModel.UserDN.IsNull() {
		tfModel.UserDN = types.StringValue(apiModel.UserDN)
	}

	if !tfModel.UserAttr.IsNull() {
		tfModel.UserAttr = types.StringValue(apiModel.UserAttr)
	}

	if !tfModel.UserFilter.IsNull() {
		tfModel.UserFilter = types.StringValue(apiModel.UserFilter)
	}

	if !tfModel.GroupDN.IsNull() {
		tfModel.GroupDN = types.StringValue(apiModel.GroupDN)
	}

	if !tfModel.GroupFilter.IsNull() {
		tfModel.GroupFilter = types.StringValue(apiModel.GroupFilter)
	}

	if !tfModel.GroupAttr.IsNull() {
		tfModel.GroupAttr = types.StringValue(apiModel.GroupAttr)
	}

	if !tfModel.AnonymousGroupSearch.IsNull() {
		tfModel.AnonymousGroupSearch = types.BoolValue(apiModel.AnonymousGroupSearch)
	}

	if !tfModel.UseTokenGroups.IsNull() {
		tfModel.UseTokenGroups = types.BoolValue(apiModel.UseTokenGroups)
	}

	if !tfModel.CaseSensitiveNames.IsNull() {
		tfModel.CaseSensitiveNames = types.BoolValue(apiModel.CaseSensitiveNames)
	}

	if !tfModel.StartTLS.IsNull() {
		tfModel.StartTLS = types.BoolValue(apiModel.StartTLS)
	}

	if !tfModel.InsecureTLS.IsNull() {
		tfModel.InsecureTLS = types.BoolValue(apiModel.InsecureTLS)
	}

	if !tfModel.TLSMinVersion.IsNull() {
		tfModel.TLSMinVersion = types.StringValue(apiModel.TLSMinVersion)
	}

	if !tfModel.TLSMaxVersion.IsNull() {
		tfModel.TLSMaxVersion = types.StringValue(apiModel.TLSMaxVersion)
	}

	if !tfModel.Certificate.IsNull() {
		tfModel.Certificate = types.StringValue(apiModel.Certificate)
	}

	if !tfModel.DiscoverDN.IsNull() {
		tfModel.DiscoverDN = types.BoolValue(apiModel.DiscoverDN)
	}

	tfModel.DenyNullBind = types.BoolValue(apiModel.DenyNullBind)

	if !tfModel.UPNDomain.IsNull() {
		tfModel.UPNDomain = types.StringValue(apiModel.UPNDomain)
	}

	if !tfModel.RequestTimeout.IsNull() {
		tfModel.RequestTimeout = types.Int64Value(apiModel.RequestTimeout)
	}

	if !tfModel.ConnectionTimeout.IsNull() {
		tfModel.ConnectionTimeout = types.Int64Value(apiModel.ConnectionTimeout)
	}

	if !tfModel.UsernameAsAlias.IsNull() {
		tfModel.UsernameAsAlias = types.BoolValue(apiModel.UsernameAsAlias)
	}

	if !tfModel.DereferenceAliases.IsNull() {
		tfModel.DereferenceAliases = types.StringValue(apiModel.DereferenceAliases)
	}

	if !tfModel.MaxPageSize.IsNull() {
		tfModel.MaxPageSize = types.Int64Value(apiModel.MaxPageSize)
	}

	if !tfModel.EnableSAMAccountNameLogin.IsNull() {
		tfModel.EnableSAMAccountNameLogin = types.BoolValue(apiModel.EnableSAMAccountNameLogin)
	}

	savedAliasMetadata := tfModel.AliasMetadata
	savedEnableSAMAccountNameLogin := tfModel.EnableSAMAccountNameLogin

	// Populate token fields using the token package helper
	diags.Append(token.PopulateTokenModelFromAPI(ctx, &tfModel.TokenModel, &apiModel.TokenAPIModel)...)

	if r.Meta() == nil || !r.Meta().IsAPISupported(provider.VaultVersion121) {
		tfModel.AliasMetadata = savedAliasMetadata
	}

	if r.Meta() == nil || !r.Meta().IsAPISupported(provider.VaultVersion119) {
		tfModel.EnableSAMAccountNameLogin = savedEnableSAMAccountNameLogin
	}

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

	resp.Diagnostics.Append(r.writeConfigWithState(ctx, &plan, &config, &state)...)
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

	mount := state.Mount.ValueString()
	configPath := fmt.Sprintf("/auth/%s/config/ldap", mount)

	// Configuration endpoints cannot be deleted from Vault, only the auth mount itself can be deleted.
	// This function only removes the resource from Terraform state.
	log.Printf("[DEBUG] Removing Kerberos LDAP config from Terraform state")

	resp.Diagnostics.AddWarning(
		"Configuration Remains in Vault",
		fmt.Sprintf("The Kerberos LDAP configuration at %q has been removed from Terraform state, "+
			"but it may still exist in Vault unless the auth mount itself is deleted.", configPath),
	)
}

func (r *kerberosAuthBackendLDAPConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldMount), req, resp)

	mount, err := extractLDAPConfigMountFromID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier '%s' is not valid: %s", req.ID, err.Error()),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(fieldMount), mount)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		log.Printf("[DEBUG] Environment variable %s set, attempting TF state import with namespace: %s", consts.EnvVarVaultNamespaceImport, ns)
		resp.Diagnostics.Append(
			resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}

// extractLDAPConfigMountFromID extracts the auth backend mount from the import identifier provided
// by the terraform import CLI command.
func extractLDAPConfigMountFromID(id string) (string, error) {
	// Trim leading/trailing slashes and whitespace
	id = strings.TrimSpace(strings.Trim(id, "/"))

	if id == "" {
		return "", fmt.Errorf("Expected import ID format: auth/{mount}/config/ldap")
	}

	// Extract mount using regex - FindStringSubmatch returns nil if no match
	matches := ldapConfigPathRegexp.FindStringSubmatch(id)
	if len(matches) != 2 || strings.TrimSpace(matches[1]) == "" {
		return "", fmt.Errorf("Expected import ID format: auth/{mount}/config/ldap")
	}

	return strings.TrimSpace(matches[1]), nil
}
