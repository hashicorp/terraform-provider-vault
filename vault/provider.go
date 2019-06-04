package vault

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/logging"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/config"
)

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_ADDR", nil),
				Description: "URL of the root of the target Vault server.",
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_TOKEN", ""),
				Description: "Token to use to authenticate to Vault.",
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
				DefaultFunc: schema.EnvDefaultFunc("VAULT_SKIP_VERIFY", ""),
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

				Description: "Maximum TTL for secret leases requested by this provider",
			},
			"max_retries": {
				Type:     schema.TypeInt,
				Optional: true,

				DefaultFunc: schema.EnvDefaultFunc("VAULT_MAX_RETRIES", 2),
				Description: "Maximum number of retries when a 5xx error code is encountered.",
			},
			"namespace": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_NAMESPACE", ""),
				Description: "The namespace to use. Available only for Vault Enterprise",
			},
		},

		ConfigureFunc: providerConfigure,

		DataSourcesMap: map[string]*schema.Resource{
			"vault_approle_auth_backend_role_id":   approleAuthBackendRoleIDDataSource(),
			"vault_kubernetes_auth_backend_config": kubernetesAuthBackendConfigDataSource(),
			"vault_kubernetes_auth_backend_role":   kubernetesAuthBackendRoleDataSource(),
			"vault_aws_access_credentials":         awsAccessCredentialsDataSource(),
			"vault_generic_secret":                 genericSecretDataSource(),
			"vault_policy_document":                policyDocumentDataSource(),
		},

		ResourcesMap: map[string]*schema.Resource{
			"vault_approle_auth_backend_login":                   approleAuthBackendLoginResource(),
			"vault_approle_auth_backend_role":                    approleAuthBackendRoleResource(),
			"vault_approle_auth_backend_role_secret_id":          approleAuthBackendRoleSecretIDResource(),
			"vault_auth_backend":                                 authBackendResource(),
			"vault_token":                                        tokenResource(),
			"vault_token_auth_backend_role":                      tokenAuthBackendRoleResource(),
			"vault_aws_auth_backend_cert":                        awsAuthBackendCertResource(),
			"vault_aws_auth_backend_client":                      awsAuthBackendClientResource(),
			"vault_aws_auth_backend_identity_whitelist":          awsAuthBackendIdentityWhitelistResource(),
			"vault_aws_auth_backend_login":                       awsAuthBackendLoginResource(),
			"vault_aws_auth_backend_role":                        awsAuthBackendRoleResource(),
			"vault_aws_auth_backend_role_tag":                    awsAuthBackendRoleTagResource(),
			"vault_aws_auth_backend_roletag_blacklist":           awsAuthBackendRoleTagBlacklistResource(),
			"vault_aws_auth_backend_sts_role":                    awsAuthBackendSTSRoleResource(),
			"vault_aws_secret_backend":                           awsSecretBackendResource(),
			"vault_aws_secret_backend_role":                      awsSecretBackendRoleResource(),
			"vault_azure_auth_backend_config":                    azureAuthBackendConfigResource(),
			"vault_azure_auth_backend_role":                      azureAuthBackendRoleResource(),
			"vault_consul_secret_backend":                        consulSecretBackendResource(),
			"vault_database_secret_backend_connection":           databaseSecretBackendConnectionResource(),
			"vault_database_secret_backend_role":                 databaseSecretBackendRoleResource(),
			"vault_github_auth_backend":                          githubAuthBackendResource(),
			"vault_github_team":                                  githubTeamResource(),
			"vault_github_user":                                  githubUserResource(),
			"vault_gcp_auth_backend":                             gcpAuthBackendResource(),
			"vault_gcp_auth_backend_role":                        gcpAuthBackendRoleResource(),
			"vault_gcp_secret_backend":                           gcpSecretBackendResource(),
			"vault_gcp_secret_roleset":                           gcpSecretRolesetResource(),
			"vault_cert_auth_backend_role":                       certAuthBackendRoleResource(),
			"vault_generic_endpoint":                             genericEndpointResource(),
			"vault_generic_secret":                               genericSecretResource(),
			"vault_jwt_auth_backend":                             jwtAuthBackendResource(),
			"vault_jwt_auth_backend_role":                        jwtAuthBackendRoleResource(),
			"vault_kubernetes_auth_backend_config":               kubernetesAuthBackendConfigResource(),
			"vault_kubernetes_auth_backend_role":                 kubernetesAuthBackendRoleResource(),
			"vault_okta_auth_backend":                            oktaAuthBackendResource(),
			"vault_okta_auth_backend_user":                       oktaAuthBackendUserResource(),
			"vault_okta_auth_backend_group":                      oktaAuthBackendGroupResource(),
			"vault_ldap_auth_backend":                            ldapAuthBackendResource(),
			"vault_ldap_auth_backend_user":                       ldapAuthBackendUserResource(),
			"vault_ldap_auth_backend_group":                      ldapAuthBackendGroupResource(),
			"vault_policy":                                       policyResource(),
			"vault_egp_policy":                                   egpPolicyResource(),
			"vault_rgp_policy":                                   rgpPolicyResource(),
			"vault_mount":                                        mountResource(),
			"vault_namespace":                                    namespaceResource(),
			"vault_audit":                                        auditResource(),
			"vault_ssh_secret_backend_ca":                        sshSecretBackendCAResource(),
			"vault_ssh_secret_backend_role":                      sshSecretBackendRoleResource(),
			"vault_identity_entity":                              identityEntityResource(),
			"vault_identity_entity_alias":                        identityEntityAliasResource(),
			"vault_identity_group":                               identityGroupResource(),
			"vault_identity_group_alias":                         identityGroupAliasResource(),
			"vault_identity_group_policies":                      identityGroupPoliciesResource(),
			"vault_rabbitmq_secret_backend":                      rabbitmqSecretBackendResource(),
			"vault_rabbitmq_secret_backend_role":                 rabbitmqSecretBackendRoleResource(),
			"vault_pki_secret_backend":                           pkiSecretBackendResource(),
			"vault_pki_secret_backend_cert":                      pkiSecretBackendCertResource(),
			"vault_pki_secret_backend_config_ca":                 pkiSecretBackendConfigCAResource(),
			"vault_pki_secret_backend_config_urls":               pkiSecretBackendConfigUrlsResource(),
			"vault_pki_secret_backend_intermediate_cert_request": pkiSecretBackendIntermediateCertRequestResource(),
			"vault_pki_secret_backend_intermediate_set_signed":   pkiSecretBackendIntermediateSetSignedResource(),
			"vault_pki_secret_backend_role":                      pkiSecretBackendRoleResource(),
			"vault_pki_secret_backend_root_cert":                 pkiSecretBackendRootCertResource(),
			"vault_pki_secret_backend_root_sign_intermediate":    pkiSecretBackendRootSignIntermediateResource(),
			"vault_pki_secret_backend_sign":                      pkiSecretBackendSignResource(),
		},
	}
}

func providerToken(d *schema.ResourceData) (string, error) {
	if token := d.Get("token").(string); token != "" {
		return token, nil
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

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	clientConfig := api.DefaultConfig()
	addr := d.Get("address").(string)
	if addr != "" {
		clientConfig.Address = addr
	}

	clientAuthI := d.Get("client_auth").([]interface{})
	if len(clientAuthI) > 1 {
		return nil, fmt.Errorf("client_auth block may appear only once")
	}

	clientAuthCert := ""
	clientAuthKey := ""
	if len(clientAuthI) == 1 {
		clientAuth := clientAuthI[0].(map[string]interface{})
		clientAuthCert = clientAuth["cert_file"].(string)
		clientAuthKey = clientAuth["key_file"].(string)
	}

	err := clientConfig.ConfigureTLS(&api.TLSConfig{
		CACert:   d.Get("ca_cert_file").(string),
		CAPath:   d.Get("ca_cert_dir").(string),
		Insecure: d.Get("skip_tls_verify").(bool),

		ClientCert: clientAuthCert,
		ClientKey:  clientAuthKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS for Vault API: %s", err)
	}

	clientConfig.HttpClient.Transport = logging.NewTransport("Vault", clientConfig.HttpClient.Transport)

	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure Vault API: %s", err)
	}

	client.SetMaxRetries(d.Get("max_retries").(int))

	token, err := providerToken(d)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("no vault token found")
	}
	client.SetToken(token)

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
	tokenInfo, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return nil, err
	}
	if tokenNamespaceRaw, ok := tokenInfo.Data["namespace_path"]; ok {
		tokenNamespace := tokenNamespaceRaw.(string)
		if tokenNamespace != "" {
			client.SetNamespace(tokenNamespace)
		}
	}

	renewable := false
	childTokenLease, err := client.Auth().Token().Create(&api.TokenCreateRequest{
		DisplayName:    "terraform",
		TTL:            fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		ExplicitMaxTTL: fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		Renewable:      &renewable,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create limited child token: %s", err)
	}

	childToken := childTokenLease.Auth.ClientToken
	policies := childTokenLease.Auth.Policies

	log.Printf("[INFO] Using Vault token with the following policies: %s", strings.Join(policies, ", "))

	// Set tht token to the generated child token
	client.SetToken(childToken)

	// Set the namespace to the requested namespace, if provided
	namespace := d.Get("namespace").(string)
	if namespace != "" {
		client.SetNamespace(namespace)
	}
	return client, nil
}
