package vault

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/config"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/vault/consts"
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
	DefaultMaxHTTPRetries = 2

	// DefaultMaxHTTPRetriesCCC is used for configuring the api.Client's MaxRetries
	// for Client Controlled Consistency related operations.
	DefaultMaxHTTPRetriesCCC = 10
)

var maxHTTPRetriesCCC int

// This is a global MutexKV for use within this provider.
// Use this when you need to have multiple resources or even multiple instances
// of the same resource write to the same path in Vault.
// The key of the mutex should be the path in Vault.
var vaultMutexKV = helper.NewMutexKV()

func Provider() *schema.Provider {
	dataSourcesMap, err := parse(DataSourceRegistry)
	if err != nil {
		panic(err)
	}
	resourcesMap, err := parse(ResourceRegistry)
	if err != nil {
		panic(err)
	}
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_ADDR", nil),
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
				DefaultFunc: schema.EnvDefaultFunc("VAULT_TOKEN", ""),
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
			"ca_cert_file": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_CACERT", ""),
				Description: "Path to a CA certificate file to validate the server's certificate.",
			},
			"ca_cert_dir": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_CAPATH", ""),
				Description: "Path to directory containing CA certificate files to validate the server's certificate.",
			},
			"auth_login": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Login to vault with an existing auth method using auth/<mount>/login",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						consts.FieldPath: {
							Type:     schema.TypeString,
							Required: true,
						},
						consts.FieldNamespace: {
							Type:     schema.TypeString,
							Optional: true,
						},
						consts.FieldParameters: {
							Type:     schema.TypeMap,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						consts.FieldMethod: {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"client_auth": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Client authentication credentials.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cert_file": {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc("VAULT_CLIENT_CERT", ""),
							Description: "Path to a file containing the client certificate.",
						},
						"key_file": {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc("VAULT_CLIENT_KEY", ""),
							Description: "Path to a file containing the private key that the certificate was issued for.",
						},
					},
				},
			},
			"skip_tls_verify": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_SKIP_VERIFY", false),
				Description: "Set this to true only if the target Vault server is an insecure development instance.",
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
				DefaultFunc: schema.EnvDefaultFunc("VAULT_MAX_RETRIES", DefaultMaxHTTPRetries),
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
		},
		ConfigureFunc:  NewProviderMeta,
		DataSourcesMap: dataSourcesMap,
		ResourcesMap:   resourcesMap,
	}
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
			Resource:      updateSchemaResource(approleAuthBackendRoleIDDataSource()),
			PathInventory: []string{"/auth/approle/role/{role_name}/role-id"},
		},
		"vault_identity_entity": {
			Resource:      updateSchemaResource(identityEntityDataSource()),
			PathInventory: []string{"/identity/lookup/entity"},
		},
		"vault_identity_group": {
			Resource:      updateSchemaResource(identityGroupDataSource()),
			PathInventory: []string{"/identity/lookup/group"},
		},
		"vault_kubernetes_auth_backend_config": {
			Resource:      updateSchemaResource(kubernetesAuthBackendConfigDataSource()),
			PathInventory: []string{"/auth/kubernetes/config"},
		},
		"vault_kubernetes_auth_backend_role": {
			Resource:      updateSchemaResource(kubernetesAuthBackendRoleDataSource()),
			PathInventory: []string{"/auth/kubernetes/role/{name}"},
		},
		"vault_ad_access_credentials": {
			Resource:      updateSchemaResource(adAccessCredentialsDataSource()),
			PathInventory: []string{"/ad/creds/{role}"},
		},
		"vault_nomad_access_token": {
			Resource:      updateSchemaResource(nomadAccessCredentialsDataSource()),
			PathInventory: []string{"/nomad/creds/{role}"},
		},
		"vault_aws_access_credentials": {
			Resource:      updateSchemaResource(awsAccessCredentialsDataSource()),
			PathInventory: []string{"/aws/creds"},
		},
		"vault_azure_access_credentials": {
			Resource:      updateSchemaResource(azureAccessCredentialsDataSource()),
			PathInventory: []string{"/azure/creds/{role}"},
		},
		"vault_generic_secret": {
			Resource:      updateSchemaResource(genericSecretDataSource()),
			PathInventory: []string{"/secret/data/{path}"},
		},
		"vault_policy_document": {
			Resource:      updateSchemaResource(policyDocumentDataSource()),
			PathInventory: []string{"/sys/policy/{name}"},
		},
		"vault_auth_backend": {
			Resource:      updateSchemaResource(authBackendDataSource()),
			PathInventory: []string{"/sys/auth"},
		},
		"vault_transit_encrypt": {
			Resource:      updateSchemaResource(transitEncryptDataSource()),
			PathInventory: []string{"/transit/encrypt/{name}"},
		},
		"vault_transit_decrypt": {
			Resource:      updateSchemaResource(transitDecryptDataSource()),
			PathInventory: []string{"/transit/decrypt/{name}"},
		},
		"vault_gcp_auth_backend_role": {
			Resource:      updateSchemaResource(gcpAuthBackendRoleDataSource()),
			PathInventory: []string{"/auth/gcp/role/{role_name}"},
		},
	}

	ResourceRegistry = map[string]*Description{
		"vault_alicloud_auth_backend_role": {
			Resource:      updateSchemaResource(alicloudAuthBackendRoleResource()),
			PathInventory: []string{"/auth/alicloud/role/{name}"},
		},
		"vault_approle_auth_backend_login": {
			Resource:      updateSchemaResource(approleAuthBackendLoginResource()),
			PathInventory: []string{"/auth/approle/login"},
		},
		"vault_approle_auth_backend_role": {
			Resource:      updateSchemaResource(approleAuthBackendRoleResource()),
			PathInventory: []string{"/auth/approle/role/{role_name}"},
		},
		"vault_approle_auth_backend_role_secret_id": {
			Resource: updateSchemaResource(approleAuthBackendRoleSecretIDResource("vault_approle_auth_backend_role_secret_id")),
			PathInventory: []string{
				"/auth/approle/role/{role_name}/secret-id",
				"/auth/approle/role/{role_name}/custom-secret-id",
			},
		},
		"vault_auth_backend": {
			Resource:      updateSchemaResource(AuthBackendResource()),
			PathInventory: []string{"/sys/auth/{path}"},
		},
		"vault_token": {
			Resource: updateSchemaResource(tokenResource()),
			PathInventory: []string{
				"/auth/token/create",
				"/auth/token/create-orphan",
				"/auth/token/create/{role_name}",
			},
		},
		"vault_token_auth_backend_role": {
			Resource:      updateSchemaResource(tokenAuthBackendRoleResource()),
			PathInventory: []string{"/auth/token/roles/{role_name}"},
		},
		"vault_ad_secret_backend": {
			Resource:      updateSchemaResource(adSecretBackendResource()),
			PathInventory: []string{"/ad"},
		},
		"vault_ad_secret_library": {
			Resource:      updateSchemaResource(adSecretBackendLibraryResource()),
			PathInventory: []string{"/ad/library/{name}"},
		},
		"vault_ad_secret_role": {
			Resource:      updateSchemaResource(adSecretBackendRoleResource()),
			PathInventory: []string{"/ad/roles/{role}"},
		},
		"vault_aws_auth_backend_cert": {
			Resource:      updateSchemaResource(awsAuthBackendCertResource()),
			PathInventory: []string{"/auth/aws/config/certificate/{cert_name}"},
		},
		"vault_aws_auth_backend_client": {
			Resource:      updateSchemaResource(awsAuthBackendClientResource()),
			PathInventory: []string{"/auth/aws/config/client"},
		},
		"vault_aws_auth_backend_identity_whitelist": {
			Resource:      updateSchemaResource(awsAuthBackendIdentityWhitelistResource()),
			PathInventory: []string{"/auth/aws/config/tidy/identity-whitelist"},
		},
		"vault_aws_auth_backend_login": {
			Resource:      updateSchemaResource(awsAuthBackendLoginResource()),
			PathInventory: []string{"/auth/aws/login"},
		},
		"vault_aws_auth_backend_role": {
			Resource:      updateSchemaResource(awsAuthBackendRoleResource()),
			PathInventory: []string{"/auth/aws/role/{role}"},
		},
		"vault_aws_auth_backend_role_tag": {
			Resource:      updateSchemaResource(awsAuthBackendRoleTagResource()),
			PathInventory: []string{"/auth/aws/role/{role}/tag"},
		},
		"vault_aws_auth_backend_roletag_blacklist": {
			Resource:      updateSchemaResource(awsAuthBackendRoleTagBlacklistResource()),
			PathInventory: []string{"/auth/aws/config/tidy/roletag-blacklist"},
		},
		"vault_aws_auth_backend_sts_role": {
			Resource:      updateSchemaResource(awsAuthBackendSTSRoleResource()),
			PathInventory: []string{"/auth/aws/config/sts/{account_id}"},
		},
		"vault_aws_secret_backend": {
			Resource:      updateSchemaResource(awsSecretBackendResource()),
			PathInventory: []string{"/aws/config/root"},
		},
		"vault_aws_secret_backend_role": {
			Resource:      updateSchemaResource(awsSecretBackendRoleResource("vault_aws_secret_backend_role")),
			PathInventory: []string{"/aws/roles/{name}"},
		},
		"vault_azure_secret_backend": {
			Resource:      updateSchemaResource(azureSecretBackendResource()),
			PathInventory: []string{"/azure/config"},
		},
		"vault_azure_secret_backend_role": {
			Resource:      updateSchemaResource(azureSecretBackendRoleResource()),
			PathInventory: []string{"/azure/roles/{name}"},
		},
		"vault_azure_auth_backend_config": {
			Resource:      updateSchemaResource(azureAuthBackendConfigResource()),
			PathInventory: []string{"/auth/azure/config"},
		},
		"vault_azure_auth_backend_role": {
			Resource:      updateSchemaResource(azureAuthBackendRoleResource()),
			PathInventory: []string{"/auth/azure/role/{name}"},
		},
		"vault_consul_secret_backend": {
			Resource:      updateSchemaResource(consulSecretBackendResource()),
			PathInventory: []string{"/consul/config/access"},
		},
		"vault_consul_secret_backend_role": {
			Resource:      updateSchemaResource(consulSecretBackendRoleResource()),
			PathInventory: []string{"/consul/roles/{name}"},
		},
		"vault_database_secret_backend_connection": {
			Resource:      updateSchemaResource(databaseSecretBackendConnectionResource()),
			PathInventory: []string{"/database/config/{name}"},
		},
		"vault_database_secret_backend_role": {
			Resource:      updateSchemaResource(databaseSecretBackendRoleResource()),
			PathInventory: []string{"/database/roles/{name}"},
		},
		"vault_database_secret_backend_static_role": {
			Resource:      updateSchemaResource(databaseSecretBackendStaticRoleResource()),
			PathInventory: []string{"/database/static-roles/{name}"},
		},
		"vault_github_auth_backend": {
			Resource:      updateSchemaResource(githubAuthBackendResource()),
			PathInventory: []string{"/auth/github/config"},
		},
		"vault_github_team": {
			Resource:      updateSchemaResource(githubTeamResource()),
			PathInventory: []string{"/auth/github/map/teams"},
		},
		"vault_github_user": {
			Resource:      updateSchemaResource(githubUserResource()),
			PathInventory: []string{"/auth/github/map/users"},
		},
		"vault_gcp_auth_backend": {
			Resource:      updateSchemaResource(gcpAuthBackendResource()),
			PathInventory: []string{"/auth/gcp/config"},
		},
		"vault_gcp_auth_backend_role": {
			Resource:      updateSchemaResource(gcpAuthBackendRoleResource()),
			PathInventory: []string{"/auth/gcp/role/{name}"},
		},
		"vault_gcp_secret_backend": {
			Resource:      updateSchemaResource(gcpSecretBackendResource("vault_gcp_secret_backend")),
			PathInventory: []string{"/gcp/config"},
		},
		"vault_gcp_secret_roleset": {
			Resource:      updateSchemaResource(gcpSecretRolesetResource()),
			PathInventory: []string{"/gcp/roleset/{name}"},
		},
		"vault_gcp_secret_static_account": {
			Resource:      updateSchemaResource(gcpSecretStaticAccountResource()),
			PathInventory: []string{"/gcp/static-account/{name}"},
		},
		"vault_cert_auth_backend_role": {
			Resource:      updateSchemaResource(certAuthBackendRoleResource()),
			PathInventory: []string{"/auth/cert/certs/{name}"},
		},
		"vault_generic_endpoint": {
			Resource:      updateSchemaResource(genericEndpointResource("vault_generic_endpoint")),
			PathInventory: []string{GenericPath},
		},
		"vault_generic_secret": {
			Resource:      updateSchemaResource(genericSecretResource("vault_generic_secret")),
			PathInventory: []string{GenericPath},
		},
		"vault_jwt_auth_backend": {
			Resource:      updateSchemaResource(jwtAuthBackendResource()),
			PathInventory: []string{"/auth/jwt/config"},
		},
		"vault_jwt_auth_backend_role": {
			Resource:      updateSchemaResource(jwtAuthBackendRoleResource()),
			PathInventory: []string{"/auth/jwt/role/{name}"},
		},
		"vault_kubernetes_auth_backend_config": {
			Resource:      updateSchemaResource(kubernetesAuthBackendConfigResource()),
			PathInventory: []string{"/auth/kubernetes/config"},
		},
		"vault_kubernetes_auth_backend_role": {
			Resource:      updateSchemaResource(kubernetesAuthBackendRoleResource()),
			PathInventory: []string{"/auth/kubernetes/role/{name}"},
		},
		"vault_okta_auth_backend": {
			Resource:      updateSchemaResource(oktaAuthBackendResource()),
			PathInventory: []string{"/auth/okta/config"},
		},
		"vault_okta_auth_backend_user": {
			Resource:      updateSchemaResource(oktaAuthBackendUserResource()),
			PathInventory: []string{"/auth/okta/users/{name}"},
		},
		"vault_okta_auth_backend_group": {
			Resource:      updateSchemaResource(oktaAuthBackendGroupResource()),
			PathInventory: []string{"/auth/okta/groups/{name}"},
		},
		"vault_ldap_auth_backend": {
			Resource:      updateSchemaResource(ldapAuthBackendResource()),
			PathInventory: []string{"/auth/ldap/config"},
		},
		"vault_ldap_auth_backend_user": {
			Resource:      updateSchemaResource(ldapAuthBackendUserResource()),
			PathInventory: []string{"/auth/ldap/users/{name}"},
		},
		"vault_ldap_auth_backend_group": {
			Resource:      updateSchemaResource(ldapAuthBackendGroupResource()),
			PathInventory: []string{"/auth/ldap/groups/{name}"},
		},
		"vault_nomad_secret_backend": {
			Resource: updateSchemaResource(nomadSecretAccessBackendResource()),
			PathInventory: []string{
				"/nomad",
				"/nomad/config/access",
				"/nomad/config/lease",
			},
		},
		"vault_nomad_secret_role": {
			Resource:      updateSchemaResource(nomadSecretBackendRoleResource()),
			PathInventory: []string{"/nomad/role/{role}"},
		},
		"vault_policy": {
			Resource:      updateSchemaResource(policyResource()),
			PathInventory: []string{"/sys/policy/{name}"},
		},
		"vault_egp_policy": {
			Resource:       updateSchemaResource(egpPolicyResource()),
			PathInventory:  []string{"/sys/policies/egp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_rgp_policy": {
			Resource:       updateSchemaResource(rgpPolicyResource()),
			PathInventory:  []string{"/sys/policies/rgp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mfa_duo": {
			Resource:       updateSchemaResource(mfaDuoResource()),
			PathInventory:  []string{"/sys/mfa/method/duo/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mount": {
			Resource:      updateSchemaResource(MountResource()),
			PathInventory: []string{"/sys/mounts/{path}"},
		},
		"vault_namespace": {
			Resource:       updateSchemaResource(namespaceResource()),
			PathInventory:  []string{"/sys/namespaces/{path}"},
			EnterpriseOnly: true,
		},
		"vault_audit": {
			Resource:      updateSchemaResource(auditResource()),
			PathInventory: []string{"/sys/audit/{path}"},
		},
		"vault_ssh_secret_backend_ca": {
			Resource:      updateSchemaResource(sshSecretBackendCAResource()),
			PathInventory: []string{"/ssh/config/ca"},
		},
		"vault_ssh_secret_backend_role": {
			Resource:      updateSchemaResource(sshSecretBackendRoleResource()),
			PathInventory: []string{"/ssh/roles/{role}"},
		},
		"vault_identity_entity": {
			Resource:      updateSchemaResource(identityEntityResource()),
			PathInventory: []string{"/identity/entity"},
		},
		"vault_identity_entity_alias": {
			Resource:      updateSchemaResource(identityEntityAliasResource()),
			PathInventory: []string{"/identity/entity-alias"},
		},
		"vault_identity_entity_policies": {
			Resource:      updateSchemaResource(identityEntityPoliciesResource()),
			PathInventory: []string{"/identity/lookup/entity"},
		},
		"vault_identity_group": {
			Resource:      updateSchemaResource(identityGroupResource()),
			PathInventory: []string{"/identity/group"},
		},
		"vault_identity_group_alias": {
			Resource:      updateSchemaResource(identityGroupAliasResource()),
			PathInventory: []string{"/identity/group-alias"},
		},
		"vault_identity_group_member_entity_ids": {
			Resource:      updateSchemaResource(identityGroupMemberEntityIdsResource()),
			PathInventory: []string{"/identity/group/id/{id}"},
		},
		"vault_identity_group_policies": {
			Resource:      updateSchemaResource(identityGroupPoliciesResource()),
			PathInventory: []string{"/identity/lookup/group"},
		},
		"vault_identity_oidc": {
			Resource:      updateSchemaResource(identityOidc()),
			PathInventory: []string{"/identity/oidc/config"},
		},
		"vault_identity_oidc_key": {
			Resource:      updateSchemaResource(identityOidcKey()),
			PathInventory: []string{"/identity/oidc/key/{name}"},
		},
		"vault_identity_oidc_key_allowed_client_id": {
			Resource:      updateSchemaResource(identityOidcKeyAllowedClientId()),
			PathInventory: []string{"/identity/oidc/key/{name}"},
		},
		"vault_identity_oidc_role": {
			Resource:      updateSchemaResource(identityOidcRole()),
			PathInventory: []string{"/identity/oidc/role/{name}"},
		},
		"vault_rabbitmq_secret_backend": {
			Resource: updateSchemaResource(rabbitMQSecretBackendResource()),
			PathInventory: []string{
				"/rabbitmq/config/connection",
				"/rabbitmq/config/lease",
			},
		},
		"vault_rabbitmq_secret_backend_role": {
			Resource:      updateSchemaResource(rabbitMQSecretBackendRoleResource()),
			PathInventory: []string{"/rabbitmq/roles/{name}"},
		},
		"vault_password_policy": {
			Resource:      updateSchemaResource(passwordPolicyResource()),
			PathInventory: []string{"/sys/policy/password/{name}"},
		},
		"vault_pki_secret_backend_cert": {
			Resource:      updateSchemaResource(pkiSecretBackendCertResource()),
			PathInventory: []string{"/pki/issue/{role}"},
		},
		"vault_pki_secret_backend_crl_config": {
			Resource:      updateSchemaResource(pkiSecretBackendCrlConfigResource()),
			PathInventory: []string{"/pki/config/crl"},
		},
		"vault_pki_secret_backend_config_ca": {
			Resource:      updateSchemaResource(pkiSecretBackendConfigCAResource()),
			PathInventory: []string{"/pki/config/ca"},
		},
		"vault_pki_secret_backend_config_urls": {
			Resource:      updateSchemaResource(pkiSecretBackendConfigUrlsResource()),
			PathInventory: []string{"/pki/config/urls"},
		},
		"vault_pki_secret_backend_intermediate_cert_request": {
			Resource:      updateSchemaResource(pkiSecretBackendIntermediateCertRequestResource()),
			PathInventory: []string{"/pki/intermediate/generate/{exported}"},
		},
		"vault_pki_secret_backend_intermediate_set_signed": {
			Resource:      updateSchemaResource(pkiSecretBackendIntermediateSetSignedResource()),
			PathInventory: []string{"/pki/intermediate/set-signed"},
		},
		"vault_pki_secret_backend_role": {
			Resource:      updateSchemaResource(pkiSecretBackendRoleResource()),
			PathInventory: []string{"/pki/roles/{name}"},
		},
		"vault_pki_secret_backend_root_cert": {
			Resource:      updateSchemaResource(pkiSecretBackendRootCertResource()),
			PathInventory: []string{"/pki/root/generate/{exported}"},
		},
		"vault_pki_secret_backend_root_sign_intermediate": {
			Resource:      updateSchemaResource(pkiSecretBackendRootSignIntermediateResource()),
			PathInventory: []string{"/pki/root/sign-intermediate"},
		},
		"vault_pki_secret_backend_sign": {
			Resource:      updateSchemaResource(pkiSecretBackendSignResource()),
			PathInventory: []string{"/pki/sign/{role}"},
		},
		"vault_quota_lease_count": {
			Resource:      updateSchemaResource(quotaLeaseCountResource()),
			PathInventory: []string{"/sys/quotas/lease-count/{name}"},
		},
		"vault_quota_rate_limit": {
			Resource:      updateSchemaResource(quotaRateLimitResource()),
			PathInventory: []string{"/sys/quotas/rate-limit/{name}"},
		},
		"vault_terraform_cloud_secret_backend": {
			Resource:      updateSchemaResource(terraformCloudSecretBackendResource()),
			PathInventory: []string{"/terraform/config"},
		},
		"vault_terraform_cloud_secret_creds": {
			Resource:      updateSchemaResource(terraformCloudSecretCredsResource()),
			PathInventory: []string{"/terraform/creds/{role}"},
		},
		"vault_terraform_cloud_secret_role": {
			Resource:      updateSchemaResource(terraformCloudSecretRoleResource()),
			PathInventory: []string{"/terraform/role/{name}"},
		},
		"vault_transit_secret_backend_key": {
			Resource:      updateSchemaResource(transitSecretBackendKeyResource()),
			PathInventory: []string{"/transit/keys/{name}"},
		},
		"vault_transit_secret_cache_config": {
			Resource:      updateSchemaResource(transitSecretBackendCacheConfig()),
			PathInventory: []string{"/transit/cache-config"},
		},
		"vault_raft_snapshot_agent_config": {
			Resource:      updateSchemaResource(raftSnapshotAgentConfigResource()),
			PathInventory: []string{"/sys/storage/raft/snapshot-auto/config/{name}"},
		},
		"vault_raft_autopilot": {
			Resource:      updateSchemaResource(raftAutopilotConfigResource()),
			PathInventory: []string{"/sys/storage/raft/autopilot/configuration"},
		},
	}
)

func providerToken(d *schema.ResourceData) (string, error) {
	if token := d.Get("token").(string); token != "" {
		return token, nil
	}

	if addAddr := d.Get("add_address_to_env").(string); addAddr == "true" {
		if addr := d.Get("address").(string); addr != "" {
			if current, exists := os.LookupEnv("VAULT_ADDR"); exists {
				defer func() {
					os.Setenv("VAULT_ADDR", current)
				}()
			} else {
				defer func() {
					os.Unsetenv("VAULT_ADDR")
				}()
			}
			os.Setenv("VAULT_ADDR", addr)
		}
	}

	// Use ~/.vault-token, or the configured token helper.
	tokenHelper, err := config.DefaultTokenHelper()
	if err != nil {
		return "", fmt.Errorf("error getting token helper: %s", err)
	}
	token, err := tokenHelper.Get()
	if err != nil {
		return "", fmt.Errorf("error getting token: %s", err)
	}
	return strings.TrimSpace(token), nil
}

func setChildToken(d *schema.ResourceData, c *api.Client) error {
	tokenName := d.Get("token_name").(string)
	if tokenName == "" {
		tokenName = "terraform"
	}

	// In order to enforce our relatively-short lease TTL, we derive a
	// temporary child token that inherits all of the policies of the
	// token we were given but expires after max_lease_ttl_seconds.
	//
	// The intent here is that Terraform will need to re-fetch any
	// secrets on each run and so we limit the exposure risk of secrets
	// that end up stored in the Terraform state, assuming that they are
	// credentials that Vault is able to revoke.
	//
	// Caution is still required with state files since not all secrets
	// can explicitly be revoked, and this limited scope won't apply to
	// any secrets that are *written* by Terraform to Vault.

	// Set the namespace to the token's namespace only for the
	// child token creation
	tokenInfo, err := c.Auth().Token().LookupSelf()
	if err != nil {
		return err
	}
	if tokenNamespaceRaw, ok := tokenInfo.Data["namespace_path"]; ok {
		tokenNamespace := tokenNamespaceRaw.(string)
		if tokenNamespace != "" {
			c.SetNamespace(tokenNamespace)
		}
	}

	renewable := false
	childTokenLease, err := c.Auth().Token().Create(&api.TokenCreateRequest{
		DisplayName:    tokenName,
		TTL:            fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		ExplicitMaxTTL: fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		Renewable:      &renewable,
	})
	if err != nil {
		return fmt.Errorf("failed to create limited child token: %s", err)
	}

	childToken := childTokenLease.Auth.ClientToken
	policies := childTokenLease.Auth.Policies

	log.Printf("[INFO] Using Vault token with the following policies: %s", strings.Join(policies, ", "))

	// Set the token to the generated child token
	c.SetToken(childToken)

	return nil
}

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

func signAWSLogin(parameters map[string]interface{}, logger hclog.Logger) error {
	var accessKey, secretKey, securityToken string
	if val, ok := parameters["aws_access_key_id"].(string); ok {
		accessKey = val
	}

	if val, ok := parameters["aws_secret_access_key"].(string); ok {
		secretKey = val
	}

	if val, ok := parameters["aws_security_token"].(string); ok {
		securityToken = val
	}

	creds, err := awsutil.RetrieveCreds(accessKey, secretKey, securityToken, logger)
	if err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials: %s", err)
	}

	var headerValue, stsRegion string
	if val, ok := parameters["header_value"].(string); ok {
		headerValue = val
	}

	if val, ok := parameters["sts_region"].(string); ok {
		stsRegion = val
	}

	loginData, err := awsutil.GenerateLoginData(creds, headerValue, stsRegion, logger)
	if err != nil {
		return fmt.Errorf("failed to generate AWS login data: %s", err)
	}

	parameters["iam_http_request_method"] = loginData["iam_http_request_method"]
	parameters["iam_request_url"] = loginData["iam_request_url"]
	parameters["iam_request_headers"] = loginData["iam_request_headers"]
	parameters["iam_request_body"] = loginData["iam_request_body"]

	return nil
}

func addCommonSchemaFields(m map[string]*schema.Schema) map[string]*schema.Schema {
	m[consts.FieldNamespace] = &schema.Schema{
		Type:         schema.TypeString,
		Optional:     true,
		ForceNew:     true,
		Description:  "Target namespace. (requires Enterprise)",
		ValidateFunc: validateNamespace,
	}

	return m
}

// TODO: temporary solution for adding common schema fields to the current code base.
func updateSchemaResource(r *schema.Resource) *schema.Resource {
	addCommonSchemaFields(r.Schema)
	return r
}
