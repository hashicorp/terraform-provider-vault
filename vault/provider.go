// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

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
	DefaultMaxHTTPRetriesCCC = provider.DefaultMaxHTTPRetriesCCC
)

func Provider() *schema.Provider {
	// TODO: add support path inventory, probably means
	// reworking the registry init entirely.
	mfaResources, err := mfa.GetResources()
	if err != nil {
		panic(err)
	}

	return provider.NewProvider(DataSourceRegistry, ResourceRegistry, mfaResources)
}

var (
	DataSourceRegistry = map[string]*provider.Description{
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
		"vault_ldap_static_credentials": {
			Resource:      UpdateSchemaResource(ldapStaticCredDataSource()),
			PathInventory: []string{"/ldap/static-cred/{role}"},
		},
		"vault_ldap_dynamic_credentials": {
			Resource:      UpdateSchemaResource(ldapDynamicCredDataSource()),
			PathInventory: []string{"/ldap/creds/{role}"},
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
		"vault_aws_static_access_credentials": {
			Resource:      UpdateSchemaResource(awsStaticCredDataSource()),
			PathInventory: []string{"/aws/static-creds/{name}"},
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
		"vault_auth_backends": {
			Resource:      UpdateSchemaResource(authBackendsDataSource()),
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
		"vault_pki_secret_backend_issuer": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIssuerDataSource()),
			PathInventory: []string{"/pki/issuer/{issuer_ref}"},
		},
		"vault_pki_secret_backend_issuers": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIssuersDataSource()),
			PathInventory: []string{"/pki/issuers"},
		},
		"vault_pki_secret_backend_key": {
			Resource:      UpdateSchemaResource(pkiSecretBackendKeyDataSource()),
			PathInventory: []string{"/pki/key/{key_ref}"},
		},
		"vault_pki_secret_backend_keys": {
			Resource:      UpdateSchemaResource(pkiSecretBackendKeysDataSource()),
			PathInventory: []string{"/pki/keys"},
		},
		"vault_transform_encode": {
			Resource:      UpdateSchemaResource(transformEncodeDataSource()),
			PathInventory: []string{"/transform/encode/{role_name}"},
		},
		"vault_transform_decode": {
			Resource:      UpdateSchemaResource(transformDecodeDataSource()),
			PathInventory: []string{"/transform/decode/{role_name}"},
		},
	}

	ResourceRegistry = map[string]*provider.Description{
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
			Resource:      UpdateSchemaResource(awsAuthBackendConfigIdentityResource()),
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
		"vault_aws_secret_backend_static_role": {
			Resource:      UpdateSchemaResource(awsSecretBackendStaticRoleResource()),
			PathInventory: []string{"/aws/static-roles/{name}"},
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
		"vault_gcp_secret_impersonated_account": {
			Resource:      UpdateSchemaResource(gcpSecretImpersonatedAccountResource()),
			PathInventory: []string{"/gcp/impersonated-account/{name}"},
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
		"vault_ldap_secret_backend": {
			Resource:      UpdateSchemaResource(ldapSecretBackendResource()),
			PathInventory: []string{"/ldap/config"},
		},
		"vault_ldap_secret_backend_static_role": {
			Resource:      UpdateSchemaResource(ldapSecretBackendStaticRoleResource()),
			PathInventory: []string{"/ldap/static-role/{name}"},
		},
		"vault_ldap_secret_backend_dynamic_role": {
			Resource:      UpdateSchemaResource(ldapSecretBackendDynamicRoleResource()),
			PathInventory: []string{"/ldap/role/{name}"},
		},
		"vault_ldap_secret_backend_library_set": {
			Resource:      UpdateSchemaResource(ldapSecretBackendLibrarySetResource()),
			PathInventory: []string{"/ldap/library/{name}"},
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
		"vault_audit_request_header": {
			Resource:      UpdateSchemaResource(auditRequestHeaderResource()),
			PathInventory: []string{"/sys/config/auditing/request-headers/{path}"},
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
		"vault_pki_secret_backend_config_cluster": {
			Resource:      UpdateSchemaResource(pkiSecretBackendConfigClusterResource()),
			PathInventory: []string{"/pki/config/cluster"},
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
		"vault_pki_secret_backend_key": {
			Resource:      UpdateSchemaResource(pkiSecretBackendKeyResource()),
			PathInventory: []string{"/pki/key/{key_id}"},
		},
		"vault_pki_secret_backend_issuer": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIssuerResource()),
			PathInventory: []string{"/pki/issuer/{issuer_ref}"},
		},
		"vault_pki_secret_backend_config_issuers": {
			Resource:      UpdateSchemaResource(pkiSecretBackendConfigIssuers()),
			PathInventory: []string{"/pki/config/issuers"},
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
		"vault_mongodbatlas_secret_backend": {
			Resource:      UpdateSchemaResource(mongodbAtlasSecretBackendResource()),
			PathInventory: []string{"/mongodbatlas/config"},
		},
		"vault_mongodbatlas_secret_role": {
			Resource:      UpdateSchemaResource(mongodbAtlasSecretRoleResource()),
			PathInventory: []string{"/mongodbatlas/roles/{name}"},
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
		"vault_transform_transformation": {
			Resource:      UpdateSchemaResource(transformTransformationResource()),
			PathInventory: []string{"/transform/transformation/{name}"},
		},
		"vault_transform_template": {
			Resource:      UpdateSchemaResource(transformTemplateResource()),
			PathInventory: []string{"/transform/template/{name}"},
		},
		"vault_transform_role": {
			Resource:      UpdateSchemaResource(transformRoleResource()),
			PathInventory: []string{"/transform/role/{name}"},
		},
		"vault_transform_alphabet": {
			Resource:      UpdateSchemaResource(transformAlphabetResource()),
			PathInventory: []string{"/transform/alphabet/{name}"},
		},
		"vault_saml_auth_backend": {
			Resource:      UpdateSchemaResource(samlAuthBackendResource()),
			PathInventory: []string{"/auth/saml/config"},
		},
		"vault_saml_auth_backend_role": {
			Resource:      UpdateSchemaResource(samlAuthBackendRoleResource()),
			PathInventory: []string{"/auth/saml/role/{name}"},
		},
		"vault_secrets_sync_config": {
			Resource:      UpdateSchemaResource(secretsSyncConfigResource()),
			PathInventory: []string{"/sys/sync/config"},
		},
		"vault_secrets_sync_aws_destination": {
			Resource:      UpdateSchemaResource(awsSecretsSyncDestinationResource()),
			PathInventory: []string{"/sys/sync/destinations/aws-sm/{name}"},
		},
		"vault_secrets_sync_azure_destination": {
			Resource:      UpdateSchemaResource(azureSecretsSyncDestinationResource()),
			PathInventory: []string{"/sys/sync/destinations/azure-kv/{name}"},
		},
		"vault_secrets_sync_gcp_destination": {
			Resource:      UpdateSchemaResource(gcpSecretsSyncDestinationResource()),
			PathInventory: []string{"/sys/sync/destinations/gcp-sm/{name}"},
		},
		"vault_secrets_sync_gh_destination": {
			Resource:      UpdateSchemaResource(githubSecretsSyncDestinationResource()),
			PathInventory: []string{"/sys/sync/destinations/gh/{name}"},
		},
		"vault_secrets_sync_github_apps": {
			Resource:      UpdateSchemaResource(githubAppsSecretsSyncResource()),
			PathInventory: []string{"/sys/sync/github-apps/{name}"},
		},
		"vault_secrets_sync_vercel_destination": {
			Resource:      UpdateSchemaResource(vercelSecretsSyncDestinationResource()),
			PathInventory: []string{"/sys/sync/destinations/vercel-project/{name}"},
		},
		"vault_secrets_sync_association": {
			Resource:      UpdateSchemaResource(secretsSyncAssociationResource()),
			PathInventory: []string{"/sys/sync/destinations/{type}/{name}/associations/set"},
		},
		"vault_config_ui_custom_message": {
			Resource:      UpdateSchemaResource(configUICustomMessageResource()),
			PathInventory: []string{"/sys/config/ui/custom-messages"},
		},
	}
)

func UpdateSchemaResource(r *schema.Resource) *schema.Resource {
	provider.MustAddSchema(r, provider.GetNamespaceSchema())

	return r
}
