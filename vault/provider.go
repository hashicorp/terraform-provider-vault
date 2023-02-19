// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/mfa"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	// GenericPath is used for inventorying paths that can be used for
	// multiple endpoints in Vault.
	GenericPath = "generic"

	// UnknownPath is used for inventorying paths that have no obvious
	// current endpoint they serve in Vault, and may relate to previous
	// versions of Vault.
	// We aim to deprecate items in this category.
	UnknownPath = "unknown"

	// DefaultMaxHTTPRetries is used for configuring the api.Client's MaxRetries.

	// DefaultMaxHTTPRetriesCCC is used for configuring the api.Client's MaxRetries
	// for Client Controlled Consistency related operations.
	DefaultMaxHTTPRetriesCCC = 10
)

func Provider() *schema.Provider {
	dataSourcesMap, err := parse(DataSourceRegistry)
	if err != nil {
		panic(err)
	}

	resourcesMap, err := parse(ResourceRegistry)
	if err != nil {
		panic(err)
	}

	// TODO: add support path inventory, probably means
	// reworking the registry init entirely.
	mfaResources, err := mfa.GetResources()
	if err != nil {
		panic(err)
	}

	provider.MustAddSchemaResource(mfaResources, resourcesMap, nil)

	r := &schema.Provider{
		Schema: map[string]*schema.Schema{
			consts.FieldAddress: {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc(api.EnvVaultAddress, nil),
				Description: "URL of the root of the target Vault server.",
			},
			"add_address_to_env": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     false,
				Description: "If true, adds the value of the `address` argument to the Terraform process environment.",
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc(api.EnvVaultToken, ""),
				Description: "Token to use to authenticate to Vault.",
			},
			"token_name": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_TOKEN_NAME", ""),
				Description: "Token name to use for creating the Vault child token.",
			},
			"skip_child_token": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("TERRAFORM_VAULT_SKIP_CHILD_TOKEN", false),

				// Setting to true will cause max_lease_ttl_seconds and token_name to be ignored (not used).
				// Note that this is strongly discouraged due to the potential of exposing sensitive secret data.
				Description: "Set this to true to prevent the creation of ephemeral child token used by this provider.",
			},
			consts.FieldCACertFile: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(api.EnvVaultCACert, ""),
				Description: "Path to a CA certificate file to validate the server's certificate.",
			},
			consts.FieldCACertDir: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(api.EnvVaultCAPath, ""),
				Description: "Path to directory containing CA certificate files to validate the server's certificate.",
			},
			consts.FieldClientAuth: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Client authentication credentials.",
				MaxItems:    1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						consts.FieldCertFile: {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc(api.EnvVaultClientCert, ""),
							Description: "Path to a file containing the client certificate.",
						},
						consts.FieldKeyFile: {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc(api.EnvVaultClientKey, ""),
							Description: "Path to a file containing the private key that the certificate was issued for.",
						},
					},
				},
			},
			consts.FieldSkipTLSVerify: {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_SKIP_VERIFY", false),
				Description: "Set this to true only if the target Vault server is an insecure development instance.",
			},
			consts.FieldTLSServerName: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc(api.EnvVaultTLSServerName, ""),
				Description: "Name to use as the SNI host when connecting via TLS.",
			},
			"max_lease_ttl_seconds": {
				Type:     schema.TypeInt,
				Optional: true,

				// Default is 20min, which is intended to be enough time for
				// a reasonable Terraform run can complete but not
				// significantly longer, so that any leases are revoked shortly
				// after Terraform has finished running.
				DefaultFunc: schema.EnvDefaultFunc("TERRAFORM_VAULT_MAX_TTL", 1200),
				Description: "Maximum TTL for secret leases requested by this provider.",
			},
			"max_retries": {
				Type:        schema.TypeInt,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_MAX_RETRIES", provider.DefaultMaxHTTPRetries),
				Description: "Maximum number of retries when a 5xx error code is encountered.",
			},
			"max_retries_ccc": {
				Type:        schema.TypeInt,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_MAX_RETRIES_CCC", DefaultMaxHTTPRetriesCCC),
				Description: "Maximum number of retries for Client Controlled Consistency related operations",
			},
			consts.FieldNamespace: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_NAMESPACE", ""),
				Description: "The namespace to use. Available only for Vault Enterprise.",
			},
			"headers": {
				Type:        schema.TypeList,
				Optional:    true,
				Sensitive:   true,
				Description: "The headers to send with each Vault request.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The header name",
						},
						"value": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The header value",
						},
					},
				},
			},
			consts.FieldSkipGetVaultVersion: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Skip the dynamic fetching of the Vault server version.",
			},
			consts.FieldVaultVersionOverride: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Override the Vault server version, " +
					"which is normally determined dynamically from the target Vault server",
				ValidateDiagFunc: provider.ValidateDiagSemVer,
			},
		},
		ConfigureFunc:  provider.NewProviderMeta,
		DataSourcesMap: dataSourcesMap,
		ResourcesMap:   resourcesMap,
	}

	provider.MustAddAuthLoginSchema(r.Schema)

	return r
}

// Description is essentially a DataSource or Resource with some additional metadata
// that helps with maintaining the Terraform Vault Provider.
type Description struct {
	// PathInventory is used for taking an inventory of the supported endpoints in the
	// Terraform Vault Provider and comparing them to the endpoints noted as available in
	// Vault's OpenAPI description. A list of Vault's endpoints can be obtained by,
	// from Vault's home directory, running "$ ./scripts/gen_openapi.sh", and then by
	// drilling into the paths with "$ cat openapi.json | jq ".paths" | jq 'keys[]'".
	// Here's a short example of how paths and their path variables should be represented:
	//		"/transit/keys/{name}/config"
	//		"/transit/random"
	//		"/transit/random/{urlbytes}"
	//		"/transit/sign/{name}/{urlalgorithm}"
	PathInventory []string

	// EnterpriseOnly defaults to false, but should be marked true if a resource is enterprise only.
	EnterpriseOnly bool

	Resource *schema.Resource
}

var (
	DataSourceRegistry = map[string]*Description{
		"vault_approle_auth_backend_role_id": {
			Resource:      UpdateSchemaResource(approleAuthBackendRoleIDDataSource()),
			PathInventory: []string{"/auth/approle/role/{role_name}/role-id"},
		},
		"vault_identity_entity": {
			Resource:      UpdateSchemaResource(identityEntityDataSource()),
			PathInventory: []string{"/identity/lookup/entity"},
		},
		"vault_identity_group": {
			Resource:      UpdateSchemaResource(identityGroupDataSource()),
			PathInventory: []string{"/identity/lookup/group"},
		},
		"vault_kubernetes_auth_backend_config": {
			Resource:      UpdateSchemaResource(kubernetesAuthBackendConfigDataSource()),
			PathInventory: []string{"/auth/kubernetes/config"},
		},
		"vault_kubernetes_auth_backend_role": {
			Resource:      UpdateSchemaResource(kubernetesAuthBackendRoleDataSource()),
			PathInventory: []string{"/auth/kubernetes/role/{name}"},
		},
		"vault_namespace": {
			Resource:       UpdateSchemaResource(namespaceDataSource()),
			PathInventory:  []string{"/sys/namespaces/{path}"},
			EnterpriseOnly: true,
		},
		"vault_ad_access_credentials": {
			Resource:      UpdateSchemaResource(adAccessCredentialsDataSource()),
			PathInventory: []string{"/ad/creds/{role}"},
		},
		"vault_nomad_access_token": {
			Resource:      UpdateSchemaResource(nomadAccessCredentialsDataSource()),
			PathInventory: []string{"/nomad/creds/{role}"},
		},
		"vault_aws_access_credentials": {
			Resource:      UpdateSchemaResource(awsAccessCredentialsDataSource()),
			PathInventory: []string{"/aws/creds"},
		},
		"vault_azure_access_credentials": {
			Resource:      UpdateSchemaResource(azureAccessCredentialsDataSource()),
			PathInventory: []string{"/azure/creds/{role}"},
		},
		"vault_kubernetes_service_account_token": {
			Resource:      UpdateSchemaResource(kubernetesServiceAccountTokenDataSource()),
			PathInventory: []string{"/kubernetes/creds/{role}"},
		},
		"vault_generic_secret": {
			Resource:      UpdateSchemaResource(genericSecretDataSource()),
			PathInventory: []string{"/secret/data/{path}"},
		},
		"vault_policy_document": {
			Resource:      UpdateSchemaResource(policyDocumentDataSource()),
			PathInventory: []string{"/sys/policy/{name}"},
		},
		"vault_auth_backend": {
			Resource:      UpdateSchemaResource(authBackendDataSource()),
			PathInventory: []string{"/sys/auth"},
		},
		"vault_transit_encrypt": {
			Resource:      UpdateSchemaResource(transitEncryptDataSource()),
			PathInventory: []string{"/transit/encrypt/{name}"},
		},
		"vault_transit_decrypt": {
			Resource:      UpdateSchemaResource(transitDecryptDataSource()),
			PathInventory: []string{"/transit/decrypt/{name}"},
		},
		"vault_gcp_auth_backend_role": {
			Resource:      UpdateSchemaResource(gcpAuthBackendRoleDataSource()),
			PathInventory: []string{"/auth/gcp/role/{role_name}"},
		},
		"vault_identity_oidc_client_creds": {
			Resource:      UpdateSchemaResource(identityOIDCClientCredsDataSource()),
			PathInventory: []string{"/identity/oidc/client/{name}"},
		},
		"vault_identity_oidc_public_keys": {
			Resource:      UpdateSchemaResource(identityOIDCPublicKeysDataSource()),
			PathInventory: []string{"/identity/oidc/provider/{name}/.well-known/keys"},
		},
		"vault_identity_oidc_openid_config": {
			Resource:      UpdateSchemaResource(identityOIDCOpenIDConfigDataSource()),
			PathInventory: []string{"/identity/oidc/provider/{name}/.well-known/openid-configuration"},
		},
		"vault_kv_secret": {
			Resource:      UpdateSchemaResource(kvSecretDataSource()),
			PathInventory: []string{"/secret/{path}"},
		},
		"vault_kv_secret_v2": {
			Resource:      UpdateSchemaResource(kvSecretV2DataSource()),
			PathInventory: []string{"/secret/data/{path}/?version={version}}"},
		},
		"vault_kv_secrets_list": {
			Resource:      UpdateSchemaResource(kvSecretListDataSource()),
			PathInventory: []string{"/secret/{path}/?list=true"},
		},
		"vault_kv_secrets_list_v2": {
			Resource:      UpdateSchemaResource(kvSecretListDataSourceV2()),
			PathInventory: []string{"/secret/metadata/{path}/?list=true"},
		},
		"vault_kv_secret_subkeys_v2": {
			Resource:      UpdateSchemaResource(kvSecretSubkeysV2DataSource()),
			PathInventory: []string{"/secret/subkeys/{path}"},
		},
		"vault_raft_autopilot_state": {
			Resource:      UpdateSchemaResource(raftAutopilotStateDataSource()),
			PathInventory: []string{"/sys/storage/raft/autopilot/state"},
		},
	}

	ResourceRegistry = map[string]*Description{
		"vault_alicloud_auth_backend_role": {
			Resource:      UpdateSchemaResource(alicloudAuthBackendRoleResource()),
			PathInventory: []string{"/auth/alicloud/role/{name}"},
		},
		"vault_approle_auth_backend_login": {
			Resource:      UpdateSchemaResource(approleAuthBackendLoginResource()),
			PathInventory: []string{"/auth/approle/login"},
		},
		"vault_approle_auth_backend_role": {
			Resource:      UpdateSchemaResource(approleAuthBackendRoleResource()),
			PathInventory: []string{"/auth/approle/role/{role_name}"},
		},
		"vault_approle_auth_backend_role_secret_id": {
			Resource: UpdateSchemaResource(approleAuthBackendRoleSecretIDResource("vault_approle_auth_backend_role_secret_id")),
			PathInventory: []string{
				"/auth/approle/role/{role_name}/secret-id",
				"/auth/approle/role/{role_name}/custom-secret-id",
			},
		},
		"vault_auth_backend": {
			Resource:      UpdateSchemaResource(AuthBackendResource()),
			PathInventory: []string{"/sys/auth/{path}"},
		},
		"vault_token": {
			Resource: UpdateSchemaResource(tokenResource()),
			PathInventory: []string{
				"/auth/token/create",
				"/auth/token/create-orphan",
				"/auth/token/create/{role_name}",
			},
		},
		"vault_token_auth_backend_role": {
			Resource:      UpdateSchemaResource(tokenAuthBackendRoleResource()),
			PathInventory: []string{"/auth/token/roles/{role_name}"},
		},
		"vault_ad_secret_backend": {
			Resource:      UpdateSchemaResource(adSecretBackendResource()),
			PathInventory: []string{"/ad"},
		},
		"vault_ad_secret_library": {
			Resource:      UpdateSchemaResource(adSecretBackendLibraryResource()),
			PathInventory: []string{"/ad/library/{name}"},
		},
		"vault_ad_secret_role": {
			Resource:      UpdateSchemaResource(adSecretBackendRoleResource()),
			PathInventory: []string{"/ad/roles/{role}"},
		},
		"vault_aws_auth_backend_cert": {
			Resource:      UpdateSchemaResource(awsAuthBackendCertResource()),
			PathInventory: []string{"/auth/aws/config/certificate/{cert_name}"},
		},
		"vault_aws_auth_backend_client": {
			Resource:      UpdateSchemaResource(awsAuthBackendClientResource()),
			PathInventory: []string{"/auth/aws/config/client"},
		},
		"vault_aws_auth_backend_config_identity": {
			Resource:      awsAuthBackendConfigIdentityResource(),
			PathInventory: []string{"/auth/aws/config/identity"},
		},
		"vault_aws_auth_backend_identity_whitelist": {
			Resource:      UpdateSchemaResource(awsAuthBackendIdentityWhitelistResource()),
			PathInventory: []string{"/auth/aws/config/tidy/identity-whitelist"},
		},
		"vault_aws_auth_backend_login": {
			Resource:      UpdateSchemaResource(awsAuthBackendLoginResource()),
			PathInventory: []string{"/auth/aws/login"},
		},
		"vault_aws_auth_backend_role": {
			Resource:      UpdateSchemaResource(awsAuthBackendRoleResource()),
			PathInventory: []string{"/auth/aws/role/{role}"},
		},
		"vault_aws_auth_backend_role_tag": {
			Resource:      UpdateSchemaResource(awsAuthBackendRoleTagResource()),
			PathInventory: []string{"/auth/aws/role/{role}/tag"},
		},
		"vault_aws_auth_backend_roletag_blacklist": {
			Resource:      UpdateSchemaResource(awsAuthBackendRoleTagBlacklistResource()),
			PathInventory: []string{"/auth/aws/config/tidy/roletag-blacklist"},
		},
		"vault_aws_auth_backend_sts_role": {
			Resource:      UpdateSchemaResource(awsAuthBackendSTSRoleResource()),
			PathInventory: []string{"/auth/aws/config/sts/{account_id}"},
		},
		"vault_aws_secret_backend": {
			Resource:      UpdateSchemaResource(awsSecretBackendResource()),
			PathInventory: []string{"/aws/config/root"},
		},
		"vault_aws_secret_backend_role": {
			Resource:      UpdateSchemaResource(awsSecretBackendRoleResource("vault_aws_secret_backend_role")),
			PathInventory: []string{"/aws/roles/{name}"},
		},
		"vault_azure_secret_backend": {
			Resource:      UpdateSchemaResource(azureSecretBackendResource()),
			PathInventory: []string{"/azure/config"},
		},
		"vault_azure_secret_backend_role": {
			Resource:      UpdateSchemaResource(azureSecretBackendRoleResource()),
			PathInventory: []string{"/azure/roles/{name}"},
		},
		"vault_azure_auth_backend_config": {
			Resource:      UpdateSchemaResource(azureAuthBackendConfigResource()),
			PathInventory: []string{"/auth/azure/config"},
		},
		"vault_azure_auth_backend_role": {
			Resource:      UpdateSchemaResource(azureAuthBackendRoleResource()),
			PathInventory: []string{"/auth/azure/role/{name}"},
		},
		"vault_consul_secret_backend": {
			Resource:      UpdateSchemaResource(consulSecretBackendResource()),
			PathInventory: []string{"/consul/config/access"},
		},
		"vault_consul_secret_backend_role": {
			Resource:      UpdateSchemaResource(consulSecretBackendRoleResource()),
			PathInventory: []string{"/consul/roles/{name}"},
		},
		"vault_database_secrets_mount": {
			Resource:      UpdateSchemaResource(databaseSecretsMountResource()),
			PathInventory: []string{"/database/config/{name}"},
		},
		"vault_database_secret_backend_connection": {
			Resource:      UpdateSchemaResource(databaseSecretBackendConnectionResource()),
			PathInventory: []string{"/database/config/{name}"},
		},
		"vault_database_secret_backend_role": {
			Resource:      UpdateSchemaResource(databaseSecretBackendRoleResource()),
			PathInventory: []string{"/database/roles/{name}"},
		},
		"vault_database_secret_backend_static_role": {
			Resource:      UpdateSchemaResource(databaseSecretBackendStaticRoleResource()),
			PathInventory: []string{"/database/static-roles/{name}"},
		},
		"vault_github_auth_backend": {
			Resource:      UpdateSchemaResource(githubAuthBackendResource()),
			PathInventory: []string{"/auth/github/config"},
		},
		"vault_github_team": {
			Resource:      UpdateSchemaResource(githubTeamResource()),
			PathInventory: []string{"/auth/github/map/teams"},
		},
		"vault_github_user": {
			Resource:      UpdateSchemaResource(githubUserResource()),
			PathInventory: []string{"/auth/github/map/users"},
		},
		"vault_gcp_auth_backend": {
			Resource:      UpdateSchemaResource(gcpAuthBackendResource()),
			PathInventory: []string{"/auth/gcp/config"},
		},
		"vault_gcp_auth_backend_role": {
			Resource:      UpdateSchemaResource(gcpAuthBackendRoleResource()),
			PathInventory: []string{"/auth/gcp/role/{name}"},
		},
		"vault_gcp_secret_backend": {
			Resource:      UpdateSchemaResource(gcpSecretBackendResource("vault_gcp_secret_backend")),
			PathInventory: []string{"/gcp/config"},
		},
		"vault_gcp_secret_roleset": {
			Resource:      UpdateSchemaResource(gcpSecretRolesetResource()),
			PathInventory: []string{"/gcp/roleset/{name}"},
		},
		"vault_gcp_secret_static_account": {
			Resource:      UpdateSchemaResource(gcpSecretStaticAccountResource()),
			PathInventory: []string{"/gcp/static-account/{name}"},
		},
		"vault_cert_auth_backend_role": {
			Resource:      UpdateSchemaResource(certAuthBackendRoleResource()),
			PathInventory: []string{"/auth/cert/certs/{name}"},
		},
		"vault_generic_endpoint": {
			Resource:      UpdateSchemaResource(genericEndpointResource("vault_generic_endpoint")),
			PathInventory: []string{GenericPath},
		},
		"vault_generic_secret": {
			Resource:      UpdateSchemaResource(genericSecretResource("vault_generic_secret")),
			PathInventory: []string{GenericPath},
		},
		"vault_jwt_auth_backend": {
			Resource:      UpdateSchemaResource(jwtAuthBackendResource()),
			PathInventory: []string{"/auth/jwt/config"},
		},
		"vault_jwt_auth_backend_role": {
			Resource:      UpdateSchemaResource(jwtAuthBackendRoleResource()),
			PathInventory: []string{"/auth/jwt/role/{name}"},
		},
		"vault_kubernetes_auth_backend_config": {
			Resource:      UpdateSchemaResource(kubernetesAuthBackendConfigResource()),
			PathInventory: []string{"/auth/kubernetes/config"},
		},
		"vault_kubernetes_auth_backend_role": {
			Resource:      UpdateSchemaResource(kubernetesAuthBackendRoleResource()),
			PathInventory: []string{"/auth/kubernetes/role/{name}"},
		},
		"vault_okta_auth_backend": {
			Resource:      UpdateSchemaResource(oktaAuthBackendResource()),
			PathInventory: []string{"/auth/okta/config"},
		},
		"vault_okta_auth_backend_user": {
			Resource:      UpdateSchemaResource(oktaAuthBackendUserResource()),
			PathInventory: []string{"/auth/okta/users/{name}"},
		},
		"vault_okta_auth_backend_group": {
			Resource:      UpdateSchemaResource(oktaAuthBackendGroupResource()),
			PathInventory: []string{"/auth/okta/groups/{name}"},
		},
		"vault_ldap_auth_backend": {
			Resource:      UpdateSchemaResource(ldapAuthBackendResource()),
			PathInventory: []string{"/auth/ldap/config"},
		},
		"vault_ldap_auth_backend_user": {
			Resource:      UpdateSchemaResource(ldapAuthBackendUserResource()),
			PathInventory: []string{"/auth/ldap/users/{name}"},
		},
		"vault_ldap_auth_backend_group": {
			Resource:      UpdateSchemaResource(ldapAuthBackendGroupResource()),
			PathInventory: []string{"/auth/ldap/groups/{name}"},
		},
		"vault_nomad_secret_backend": {
			Resource: UpdateSchemaResource(nomadSecretAccessBackendResource()),
			PathInventory: []string{
				"/nomad",
				"/nomad/config/access",
				"/nomad/config/lease",
			},
		},
		"vault_nomad_secret_role": {
			Resource:      UpdateSchemaResource(nomadSecretBackendRoleResource()),
			PathInventory: []string{"/nomad/role/{role}"},
		},
		"vault_policy": {
			Resource:      UpdateSchemaResource(policyResource()),
			PathInventory: []string{"/sys/policy/{name}"},
		},
		"vault_egp_policy": {
			Resource:       UpdateSchemaResource(egpPolicyResource()),
			PathInventory:  []string{"/sys/policies/egp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_rgp_policy": {
			Resource:       UpdateSchemaResource(rgpPolicyResource()),
			PathInventory:  []string{"/sys/policies/rgp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mfa_duo": {
			Resource:       UpdateSchemaResource(mfaDuoResource()),
			PathInventory:  []string{"/sys/mfa/method/duo/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mfa_okta": {
			Resource:       UpdateSchemaResource(mfaOktaResource()),
			PathInventory:  []string{"/sys/mfa/method/okta/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mfa_totp": {
			Resource:       UpdateSchemaResource(mfaTOTPResource()),
			PathInventory:  []string{"/sys/mfa/method/totp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mfa_pingid": {
			Resource:       UpdateSchemaResource(mfaPingIDResource()),
			PathInventory:  []string{"/sys/mfa/method/totp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mount": {
			Resource:      UpdateSchemaResource(MountResource()),
			PathInventory: []string{"/sys/mounts/{path}"},
		},
		"vault_namespace": {
			Resource:       UpdateSchemaResource(namespaceResource()),
			PathInventory:  []string{"/sys/namespaces/{path}"},
			EnterpriseOnly: true,
		},
		"vault_audit": {
			Resource:      UpdateSchemaResource(auditResource()),
			PathInventory: []string{"/sys/audit/{path}"},
		},
		"vault_ssh_secret_backend_ca": {
			Resource:      UpdateSchemaResource(sshSecretBackendCAResource()),
			PathInventory: []string{"/ssh/config/ca"},
		},
		"vault_ssh_secret_backend_role": {
			Resource:      UpdateSchemaResource(sshSecretBackendRoleResource()),
			PathInventory: []string{"/ssh/roles/{role}"},
		},
		"vault_identity_entity": {
			Resource:      UpdateSchemaResource(identityEntityResource()),
			PathInventory: []string{"/identity/entity"},
		},
		"vault_identity_entity_alias": {
			Resource:      UpdateSchemaResource(identityEntityAliasResource()),
			PathInventory: []string{"/identity/entity-alias"},
		},
		"vault_identity_entity_policies": {
			Resource:      UpdateSchemaResource(identityEntityPoliciesResource()),
			PathInventory: []string{"/identity/lookup/entity"},
		},
		"vault_identity_group": {
			Resource:      UpdateSchemaResource(identityGroupResource()),
			PathInventory: []string{"/identity/group"},
		},
		"vault_identity_group_alias": {
			Resource:      UpdateSchemaResource(identityGroupAliasResource()),
			PathInventory: []string{"/identity/group-alias"},
		},
		"vault_identity_group_member_entity_ids": {
			Resource:      UpdateSchemaResource(identityGroupMemberEntityIdsResource()),
			PathInventory: []string{"/identity/group/id/{id}"},
		},
		"vault_identity_group_member_group_ids": {
			Resource:      UpdateSchemaResource(identityGroupMemberGroupIdsResource()),
			PathInventory: []string{"/identity/group/id/{id}"},
		},
		"vault_identity_group_policies": {
			Resource:      UpdateSchemaResource(identityGroupPoliciesResource()),
			PathInventory: []string{"/identity/lookup/group"},
		},
		"vault_identity_oidc": {
			Resource:      UpdateSchemaResource(identityOidc()),
			PathInventory: []string{"/identity/oidc/config"},
		},
		"vault_identity_oidc_key": {
			Resource:      UpdateSchemaResource(identityOidcKey()),
			PathInventory: []string{"/identity/oidc/key/{name}"},
		},
		"vault_identity_oidc_key_allowed_client_id": {
			Resource:      UpdateSchemaResource(identityOidcKeyAllowedClientId()),
			PathInventory: []string{"/identity/oidc/key/{name}"},
		},
		"vault_identity_oidc_role": {
			Resource:      UpdateSchemaResource(identityOidcRole()),
			PathInventory: []string{"/identity/oidc/role/{name}"},
		},
		"vault_rabbitmq_secret_backend": {
			Resource: UpdateSchemaResource(rabbitMQSecretBackendResource()),
			PathInventory: []string{
				"/rabbitmq/config/connection",
				"/rabbitmq/config/lease",
			},
		},
		"vault_rabbitmq_secret_backend_role": {
			Resource:      UpdateSchemaResource(rabbitMQSecretBackendRoleResource()),
			PathInventory: []string{"/rabbitmq/roles/{name}"},
		},
		"vault_password_policy": {
			Resource:      UpdateSchemaResource(passwordPolicyResource()),
			PathInventory: []string{"/sys/policy/password/{name}"},
		},
		"vault_pki_secret_backend_cert": {
			Resource:      UpdateSchemaResource(pkiSecretBackendCertResource()),
			PathInventory: []string{"/pki/issue/{role}"},
		},
		"vault_pki_secret_backend_crl_config": {
			Resource:      UpdateSchemaResource(pkiSecretBackendCrlConfigResource()),
			PathInventory: []string{"/pki/config/crl"},
		},
		"vault_pki_secret_backend_config_ca": {
			Resource:      UpdateSchemaResource(pkiSecretBackendConfigCAResource()),
			PathInventory: []string{"/pki/config/ca"},
		},
		"vault_pki_secret_backend_config_urls": {
			Resource:      UpdateSchemaResource(pkiSecretBackendConfigUrlsResource()),
			PathInventory: []string{"/pki/config/urls"},
		},
		"vault_pki_secret_backend_intermediate_cert_request": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIntermediateCertRequestResource()),
			PathInventory: []string{"/pki/intermediate/generate/{exported}"},
		},
		"vault_pki_secret_backend_intermediate_set_signed": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIntermediateSetSignedResource()),
			PathInventory: []string{"/pki/intermediate/set-signed"},
		},
		"vault_pki_secret_backend_role": {
			Resource:      UpdateSchemaResource(pkiSecretBackendRoleResource()),
			PathInventory: []string{"/pki/roles/{name}"},
		},
		"vault_pki_secret_backend_root_cert": {
			Resource:      UpdateSchemaResource(pkiSecretBackendRootCertResource()),
			PathInventory: []string{"/pki/root/generate/{exported}"},
		},
		"vault_pki_secret_backend_root_sign_intermediate": {
			Resource:      UpdateSchemaResource(pkiSecretBackendRootSignIntermediateResource()),
			PathInventory: []string{"/pki/root/sign-intermediate"},
		},
		"vault_pki_secret_backend_sign": {
			Resource:      UpdateSchemaResource(pkiSecretBackendSignResource()),
			PathInventory: []string{"/pki/sign/{role}"},
		},
		"vault_quota_lease_count": {
			Resource:      UpdateSchemaResource(quotaLeaseCountResource()),
			PathInventory: []string{"/sys/quotas/lease-count/{name}"},
		},
		"vault_quota_rate_limit": {
			Resource:      UpdateSchemaResource(quotaRateLimitResource()),
			PathInventory: []string{"/sys/quotas/rate-limit/{name}"},
		},
		"vault_terraform_cloud_secret_backend": {
			Resource:      UpdateSchemaResource(terraformCloudSecretBackendResource()),
			PathInventory: []string{"/terraform/config"},
		},
		"vault_terraform_cloud_secret_creds": {
			Resource:      UpdateSchemaResource(terraformCloudSecretCredsResource()),
			PathInventory: []string{"/terraform/creds/{role}"},
		},
		"vault_terraform_cloud_secret_role": {
			Resource:      UpdateSchemaResource(terraformCloudSecretRoleResource()),
			PathInventory: []string{"/terraform/role/{name}"},
		},
		"vault_transit_secret_backend_key": {
			Resource:      UpdateSchemaResource(transitSecretBackendKeyResource()),
			PathInventory: []string{"/transit/keys/{name}"},
		},
		"vault_transit_secret_cache_config": {
			Resource:      UpdateSchemaResource(transitSecretBackendCacheConfig()),
			PathInventory: []string{"/transit/cache-config"},
		},
		"vault_raft_snapshot_agent_config": {
			Resource:      UpdateSchemaResource(raftSnapshotAgentConfigResource()),
			PathInventory: []string{"/sys/storage/raft/snapshot-auto/config/{name}"},
		},
		"vault_raft_autopilot": {
			Resource:      UpdateSchemaResource(raftAutopilotConfigResource()),
			PathInventory: []string{"/sys/storage/raft/autopilot/configuration"},
		},
		"vault_kmip_secret_backend": {
			Resource:      UpdateSchemaResource(kmipSecretBackendResource()),
			PathInventory: []string{"/kmip/config"},
		},
		"vault_kmip_secret_scope": {
			Resource:      UpdateSchemaResource(kmipSecretScopeResource()),
			PathInventory: []string{"/kmip/scope/{scope}"},
		},
		"vault_kmip_secret_role": {
			Resource:      UpdateSchemaResource(kmipSecretRoleResource()),
			PathInventory: []string{"/kmip/scope/{scope}/role/{role}"},
		},
		"vault_identity_oidc_scope": {
			Resource:      UpdateSchemaResource(identityOIDCScopeResource()),
			PathInventory: []string{"/identity/oidc/scope/{scope}"},
		},
		"vault_identity_oidc_assignment": {
			Resource:      UpdateSchemaResource(identityOIDCAssignmentResource()),
			PathInventory: []string{"/identity/oidc/assignment/{name}"},
		},
		"vault_identity_oidc_client": {
			Resource:      UpdateSchemaResource(identityOIDCClientResource()),
			PathInventory: []string{"/identity/oidc/client/{name}"},
		},
		"vault_identity_oidc_provider": {
			Resource:      UpdateSchemaResource(identityOIDCProviderResource()),
			PathInventory: []string{"/identity/oidc/provider/{name}"},
		},
		"vault_kv_secret_backend_v2": {
			Resource:      UpdateSchemaResource(kvSecretBackendV2Resource()),
			PathInventory: []string{"/secret/data/{path}"},
		},
		"vault_kv_secret": {
			Resource:      UpdateSchemaResource(kvSecretResource("vault_kv_secret")),
			PathInventory: []string{"/secret/{path}"},
		},
		"vault_kv_secret_v2": {
			Resource:      UpdateSchemaResource(kvSecretV2Resource("vault_kv_secret_v2")),
			PathInventory: []string{"/secret/data/{path}"},
		},
		"vault_kubernetes_secret_backend": {
			Resource:      UpdateSchemaResource(kubernetesSecretBackendResource()),
			PathInventory: []string{"/kubernetes/config"},
		},
		"vault_kubernetes_secret_backend_role": {
			Resource:      UpdateSchemaResource(kubernetesSecretBackendRoleResource()),
			PathInventory: []string{"/kubernetes/roles/{name}"},
		},
		"vault_managed_keys": {
			Resource:      UpdateSchemaResource(managedKeysResource()),
			PathInventory: []string{"/sys/managed-keys/{type}/{name}"},
		},
	}
)

func parse(descs map[string]*Description) (map[string]*schema.Resource, error) {
	var errs error
	resourceMap := make(map[string]*schema.Resource)
	for k, desc := range descs {
		resourceMap[k] = desc.Resource
		if len(desc.PathInventory) == 0 {
			errs = multierror.Append(errs, fmt.Errorf("%q needs its paths inventoried", k))
		}
	}
	return resourceMap, errs
}

func UpdateSchemaResource(r *schema.Resource) *schema.Resource {
	provider.MustAddSchema(r, provider.GetNamespaceSchema())

	return r
}

// ReadWrapper provides common read operations to the wrapped schema.ReadFunc.
func ReadWrapper(f schema.ReadFunc) schema.ReadFunc {
	return func(d *schema.ResourceData, i interface{}) error {
		if err := importNamespace(d); err != nil {
			return err
		}

		return f(d, i)
	}
}

// ReadContextWrapper provides common read operations to the wrapped schema.ReadContextFunc.
func ReadContextWrapper(f schema.ReadContextFunc) schema.ReadContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, i interface{}) diag.Diagnostics {
		if err := importNamespace(d); err != nil {
			return diag.FromErr(err)
		}
		return f(ctx, d, i)
	}
}

// MountCreateContextWrapper performs a minimum version requirement check prior to the
// wrapped schema.CreateContextFunc.
func MountCreateContextWrapper(f schema.CreateContextFunc, minVersion *version.Version) schema.CreateContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		currentVersion := meta.(*provider.ProviderMeta).GetVaultVersion()

		if !provider.IsAPISupported(meta, minVersion) {
			return diag.Errorf("feature not enabled on current Vault version. min version required=%s; "+
				"current vault version=%s", minVersion, currentVersion)
		}

		return f(ctx, d, meta)
	}
}

func importNamespace(d *schema.ResourceData) error {
	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		s := d.State()
		if _, ok := s.Attributes[consts.FieldNamespace]; !ok {
			log.Printf(`[INFO] Environment variable %s set, `+
				`attempting TF state import "%s=%s"`,
				consts.EnvVarVaultNamespaceImport, consts.FieldNamespace, ns)
			if err := d.Set(consts.FieldNamespace, ns); err != nil {
				return fmt.Errorf("failed to import %q, err=%w",
					consts.EnvVarVaultNamespaceImport, err)
			}
		}
	}

	return nil
}
