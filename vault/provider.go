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
			Resource:      UpdateSchemaResource(approleAuthBackendRoleIDDataSource(), false),
			PathInventory: []string{"/auth/approle/role/{role_name}/role-id"},
		},
		"vault_identity_entity": {
			Resource:      UpdateSchemaResource(identityEntityDataSource(), false),
			PathInventory: []string{"/identity/lookup/entity"},
		},
		"vault_identity_group": {
			Resource:      UpdateSchemaResource(identityGroupDataSource(), false),
			PathInventory: []string{"/identity/lookup/group"},
		},
		"vault_kubernetes_auth_backend_config": {
			Resource:      UpdateSchemaResource(kubernetesAuthBackendConfigDataSource(), false),
			PathInventory: []string{"/auth/kubernetes/config"},
		},
		"vault_kubernetes_auth_backend_role": {
			Resource:      UpdateSchemaResource(kubernetesAuthBackendRoleDataSource(), false),
			PathInventory: []string{"/auth/kubernetes/role/{name}"},
		},
		"vault_ldap_static_credentials": {
			Resource:      UpdateSchemaResource(ldapStaticCredDataSource(), false),
			PathInventory: []string{"/ldap/static-cred/{role}"},
		},
		"vault_ldap_dynamic_credentials": {
			Resource:      UpdateSchemaResource(ldapDynamicCredDataSource(), false),
			PathInventory: []string{"/ldap/creds/{role}"},
		},
		"vault_ad_access_credentials": {
			Resource:      UpdateSchemaResource(adAccessCredentialsDataSource(), false),
			PathInventory: []string{"/ad/creds/{role}"},
		},
		"vault_nomad_access_token": {
			Resource:      UpdateSchemaResource(nomadAccessCredentialsDataSource(), false),
			PathInventory: []string{"/nomad/creds/{role}"},
		},
		"vault_aws_access_credentials": {
			Resource:      UpdateSchemaResource(awsAccessCredentialsDataSource(), false),
			PathInventory: []string{"/aws/creds"},
		},
		"vault_aws_static_access_credentials": {
			Resource:      UpdateSchemaResource(awsStaticCredDataSource(), false),
			PathInventory: []string{"/aws/static-creds/{name}"},
		},
		"vault_azure_access_credentials": {
			Resource:      UpdateSchemaResource(azureAccessCredentialsDataSource(), false),
			PathInventory: []string{"/azure/creds/{role}"},
		},
		"vault_kubernetes_service_account_token": {
			Resource:      UpdateSchemaResource(kubernetesServiceAccountTokenDataSource(), false),
			PathInventory: []string{"/kubernetes/creds/{role}"},
		},
		"vault_generic_secret": {
			Resource:      UpdateSchemaResource(genericSecretDataSource(), false),
			PathInventory: []string{"/secret/data/{path}"},
		},
		"vault_policy_document": {
			Resource:      UpdateSchemaResource(policyDocumentDataSource(), false),
			PathInventory: []string{"/sys/policy/{name}"},
		},
		"vault_auth_backend": {
			Resource:      UpdateSchemaResource(authBackendDataSource(), false),
			PathInventory: []string{"/sys/auth"},
		},
		"vault_auth_backends": {
			Resource:      UpdateSchemaResource(authBackendsDataSource(), false),
			PathInventory: []string{"/sys/auth"},
		},
		"vault_transit_encrypt": {
			Resource:      UpdateSchemaResource(transitEncryptDataSource(), false),
			PathInventory: []string{"/transit/encrypt/{name}"},
		},
		"vault_transit_decrypt": {
			Resource:      UpdateSchemaResource(transitDecryptDataSource(), false),
			PathInventory: []string{"/transit/decrypt/{name}"},
		},
		"vault_gcp_auth_backend_role": {
			Resource:      UpdateSchemaResource(gcpAuthBackendRoleDataSource(), false),
			PathInventory: []string{"/auth/gcp/role/{role_name}"},
		},
		"vault_identity_oidc_client_creds": {
			Resource:      UpdateSchemaResource(identityOIDCClientCredsDataSource(), false),
			PathInventory: []string{"/identity/oidc/client/{name}"},
		},
		"vault_identity_oidc_public_keys": {
			Resource:      UpdateSchemaResource(identityOIDCPublicKeysDataSource(), false),
			PathInventory: []string{"/identity/oidc/provider/{name}/.well-known/keys"},
		},
		"vault_identity_oidc_openid_config": {
			Resource:      UpdateSchemaResource(identityOIDCOpenIDConfigDataSource(), false),
			PathInventory: []string{"/identity/oidc/provider/{name}/.well-known/openid-configuration"},
		},
		"vault_kv_secret": {
			Resource:      UpdateSchemaResource(kvSecretDataSource(), false),
			PathInventory: []string{"/secret/{path}"},
		},
		"vault_kv_secret_v2": {
			Resource:      UpdateSchemaResource(kvSecretV2DataSource(), false),
			PathInventory: []string{"/secret/data/{path}/?version={version}}"},
		},
		"vault_kv_secrets_list": {
			Resource:      UpdateSchemaResource(kvSecretListDataSource(), false),
			PathInventory: []string{"/secret/{path}/?list=true"},
		},
		"vault_kv_secrets_list_v2": {
			Resource:      UpdateSchemaResource(kvSecretListDataSourceV2(), false),
			PathInventory: []string{"/secret/metadata/{path}/?list=true"},
		},
		"vault_kv_secret_subkeys_v2": {
			Resource:      UpdateSchemaResource(kvSecretSubkeysV2DataSource(), false),
			PathInventory: []string{"/secret/subkeys/{path}"},
		},
		"vault_raft_autopilot_state": {
			Resource:      UpdateSchemaResource(raftAutopilotStateDataSource(), false),
			PathInventory: []string{"/sys/storage/raft/autopilot/state"},
		},
		"vault_pki_secret_backend_issuer": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIssuerDataSource(), false),
			PathInventory: []string{"/pki/issuer/{issuer_ref}"},
		},
		"vault_pki_secret_backend_issuers": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIssuersDataSource(), false),
			PathInventory: []string{"/pki/issuers"},
		},
		"vault_pki_secret_backend_key": {
			Resource:      UpdateSchemaResource(pkiSecretBackendKeyDataSource(), false),
			PathInventory: []string{"/pki/key/{key_ref}"},
		},
		"vault_pki_secret_backend_keys": {
			Resource:      UpdateSchemaResource(pkiSecretBackendKeysDataSource(), false),
			PathInventory: []string{"/pki/keys"},
		},
	}

	ResourceRegistry = map[string]*provider.Description{
		"vault_alicloud_auth_backend_role": {
			Resource:      UpdateSchemaResource(alicloudAuthBackendRoleResource(), true),
			PathInventory: []string{"/auth/alicloud/role/{name}"},
		},
		"vault_approle_auth_backend_login": {
			Resource:      UpdateSchemaResource(approleAuthBackendLoginResource(), true),
			PathInventory: []string{"/auth/approle/login"},
		},
		"vault_approle_auth_backend_role": {
			Resource:      UpdateSchemaResource(approleAuthBackendRoleResource(), true),
			PathInventory: []string{"/auth/approle/role/{role_name}"},
		},
		"vault_approle_auth_backend_role_secret_id": {
			Resource: UpdateSchemaResource(approleAuthBackendRoleSecretIDResource("vault_approle_auth_backend_role_secret_id"), true),
			PathInventory: []string{
				"/auth/approle/role/{role_name}/secret-id",
				"/auth/approle/role/{role_name}/custom-secret-id",
			},
		},
		"vault_auth_backend": {
			Resource:      UpdateSchemaResource(AuthBackendResource(), true),
			PathInventory: []string{"/sys/auth/{path}"},
		},
		"vault_token": {
			Resource: UpdateSchemaResource(tokenResource(), true),
			PathInventory: []string{
				"/auth/token/create",
				"/auth/token/create-orphan",
				"/auth/token/create/{role_name}",
			},
		},
		"vault_token_auth_backend_role": {
			Resource:      UpdateSchemaResource(tokenAuthBackendRoleResource(), true),
			PathInventory: []string{"/auth/token/roles/{role_name}"},
		},
		"vault_ad_secret_backend": {
			Resource:      UpdateSchemaResource(adSecretBackendResource(), true),
			PathInventory: []string{"/ad"},
		},
		"vault_ad_secret_library": {
			Resource:      UpdateSchemaResource(adSecretBackendLibraryResource(), true),
			PathInventory: []string{"/ad/library/{name}"},
		},
		"vault_ad_secret_role": {
			Resource:      UpdateSchemaResource(adSecretBackendRoleResource(), true),
			PathInventory: []string{"/ad/roles/{role}"},
		},
		"vault_aws_auth_backend_cert": {
			Resource:      UpdateSchemaResource(awsAuthBackendCertResource(), true),
			PathInventory: []string{"/auth/aws/config/certificate/{cert_name}"},
		},
		"vault_aws_auth_backend_client": {
			Resource:      UpdateSchemaResource(awsAuthBackendClientResource(), true),
			PathInventory: []string{"/auth/aws/config/client"},
		},
		"vault_aws_auth_backend_config_identity": {
			Resource:      UpdateSchemaResource(awsAuthBackendConfigIdentityResource(), true),
			PathInventory: []string{"/auth/aws/config/identity"},
		},
		"vault_aws_auth_backend_identity_whitelist": {
			Resource:      UpdateSchemaResource(awsAuthBackendIdentityWhitelistResource(), true),
			PathInventory: []string{"/auth/aws/config/tidy/identity-whitelist"},
		},
		"vault_aws_auth_backend_login": {
			Resource:      UpdateSchemaResource(awsAuthBackendLoginResource(), true),
			PathInventory: []string{"/auth/aws/login"},
		},
		"vault_aws_auth_backend_role": {
			Resource:      UpdateSchemaResource(awsAuthBackendRoleResource(), true),
			PathInventory: []string{"/auth/aws/role/{role}"},
		},
		"vault_aws_auth_backend_role_tag": {
			Resource:      UpdateSchemaResource(awsAuthBackendRoleTagResource(), true),
			PathInventory: []string{"/auth/aws/role/{role}/tag"},
		},
		"vault_aws_auth_backend_roletag_blacklist": {
			Resource:      UpdateSchemaResource(awsAuthBackendRoleTagBlacklistResource(), true),
			PathInventory: []string{"/auth/aws/config/tidy/roletag-blacklist"},
		},
		"vault_aws_auth_backend_sts_role": {
			Resource:      UpdateSchemaResource(awsAuthBackendSTSRoleResource(), true),
			PathInventory: []string{"/auth/aws/config/sts/{account_id}"},
		},
		"vault_aws_secret_backend": {
			Resource:      UpdateSchemaResource(awsSecretBackendResource(), true),
			PathInventory: []string{"/aws/config/root"},
		},
		"vault_aws_secret_backend_role": {
			Resource:      UpdateSchemaResource(awsSecretBackendRoleResource("vault_aws_secret_backend_role"), true),
			PathInventory: []string{"/aws/roles/{name}"},
		},
		"vault_aws_secret_backend_static_role": {
			Resource:      UpdateSchemaResource(awsSecretBackendStaticRoleResource(), true),
			PathInventory: []string{"/aws/static-roles/{name}"},
		},
		"vault_azure_secret_backend": {
			Resource:      UpdateSchemaResource(azureSecretBackendResource(), true),
			PathInventory: []string{"/azure/config"},
		},
		"vault_azure_secret_backend_role": {
			Resource:      UpdateSchemaResource(azureSecretBackendRoleResource(), true),
			PathInventory: []string{"/azure/roles/{name}"},
		},
		"vault_azure_auth_backend_config": {
			Resource:      UpdateSchemaResource(azureAuthBackendConfigResource(), true),
			PathInventory: []string{"/auth/azure/config"},
		},
		"vault_azure_auth_backend_role": {
			Resource:      UpdateSchemaResource(azureAuthBackendRoleResource(), true),
			PathInventory: []string{"/auth/azure/role/{name}"},
		},
		"vault_consul_secret_backend": {
			Resource:      UpdateSchemaResource(consulSecretBackendResource(), true),
			PathInventory: []string{"/consul/config/access"},
		},
		"vault_consul_secret_backend_role": {
			Resource:      UpdateSchemaResource(consulSecretBackendRoleResource(), true),
			PathInventory: []string{"/consul/roles/{name}"},
		},
		"vault_database_secrets_mount": {
			Resource:      UpdateSchemaResource(databaseSecretsMountResource(), true),
			PathInventory: []string{"/database/config/{name}"},
		},
		"vault_database_secret_backend_connection": {
			Resource:      UpdateSchemaResource(databaseSecretBackendConnectionResource(), true),
			PathInventory: []string{"/database/config/{name}"},
		},
		"vault_database_secret_backend_role": {
			Resource:      UpdateSchemaResource(databaseSecretBackendRoleResource(), true),
			PathInventory: []string{"/database/roles/{name}"},
		},
		"vault_database_secret_backend_static_role": {
			Resource:      UpdateSchemaResource(databaseSecretBackendStaticRoleResource(), true),
			PathInventory: []string{"/database/static-roles/{name}"},
		},
		"vault_github_auth_backend": {
			Resource:      UpdateSchemaResource(githubAuthBackendResource(), true),
			PathInventory: []string{"/auth/github/config"},
		},
		"vault_github_team": {
			Resource:      UpdateSchemaResource(githubTeamResource(), true),
			PathInventory: []string{"/auth/github/map/teams"},
		},
		"vault_github_user": {
			Resource:      UpdateSchemaResource(githubUserResource(), true),
			PathInventory: []string{"/auth/github/map/users"},
		},
		"vault_gcp_auth_backend": {
			Resource:      UpdateSchemaResource(gcpAuthBackendResource(), true),
			PathInventory: []string{"/auth/gcp/config"},
		},
		"vault_gcp_auth_backend_role": {
			Resource:      UpdateSchemaResource(gcpAuthBackendRoleResource(), true),
			PathInventory: []string{"/auth/gcp/role/{name}"},
		},
		"vault_gcp_secret_backend": {
			Resource:      UpdateSchemaResource(gcpSecretBackendResource("vault_gcp_secret_backend"), true),
			PathInventory: []string{"/gcp/config"},
		},
		"vault_gcp_secret_impersonated_account": {
			Resource:      UpdateSchemaResource(gcpSecretImpersonatedAccountResource(), true),
			PathInventory: []string{"/gcp/impersonated-account/{name}"},
		},
		"vault_gcp_secret_roleset": {
			Resource:      UpdateSchemaResource(gcpSecretRolesetResource(), true),
			PathInventory: []string{"/gcp/roleset/{name}"},
		},
		"vault_gcp_secret_static_account": {
			Resource:      UpdateSchemaResource(gcpSecretStaticAccountResource(), true),
			PathInventory: []string{"/gcp/static-account/{name}"},
		},
		"vault_cert_auth_backend_role": {
			Resource:      UpdateSchemaResource(certAuthBackendRoleResource(), true),
			PathInventory: []string{"/auth/cert/certs/{name}"},
		},
		"vault_generic_endpoint": {
			Resource:      UpdateSchemaResource(genericEndpointResource("vault_generic_endpoint"), true),
			PathInventory: []string{GenericPath},
		},
		"vault_generic_secret": {
			Resource:      UpdateSchemaResource(genericSecretResource("vault_generic_secret"), true),
			PathInventory: []string{GenericPath},
		},
		"vault_jwt_auth_backend": {
			Resource:      UpdateSchemaResource(jwtAuthBackendResource(), true),
			PathInventory: []string{"/auth/jwt/config"},
		},
		"vault_jwt_auth_backend_role": {
			Resource:      UpdateSchemaResource(jwtAuthBackendRoleResource(), true),
			PathInventory: []string{"/auth/jwt/role/{name}"},
		},
		"vault_kubernetes_auth_backend_config": {
			Resource:      UpdateSchemaResource(kubernetesAuthBackendConfigResource(), true),
			PathInventory: []string{"/auth/kubernetes/config"},
		},
		"vault_kubernetes_auth_backend_role": {
			Resource:      UpdateSchemaResource(kubernetesAuthBackendRoleResource(), true),
			PathInventory: []string{"/auth/kubernetes/role/{name}"},
		},
		"vault_okta_auth_backend": {
			Resource:      UpdateSchemaResource(oktaAuthBackendResource(), true),
			PathInventory: []string{"/auth/okta/config"},
		},
		"vault_okta_auth_backend_user": {
			Resource:      UpdateSchemaResource(oktaAuthBackendUserResource(), true),
			PathInventory: []string{"/auth/okta/users/{name}"},
		},
		"vault_okta_auth_backend_group": {
			Resource:      UpdateSchemaResource(oktaAuthBackendGroupResource(), true),
			PathInventory: []string{"/auth/okta/groups/{name}"},
		},
		"vault_ldap_auth_backend": {
			Resource:      UpdateSchemaResource(ldapAuthBackendResource(), true),
			PathInventory: []string{"/auth/ldap/config"},
		},
		"vault_ldap_auth_backend_user": {
			Resource:      UpdateSchemaResource(ldapAuthBackendUserResource(), true),
			PathInventory: []string{"/auth/ldap/users/{name}"},
		},
		"vault_ldap_auth_backend_group": {
			Resource:      UpdateSchemaResource(ldapAuthBackendGroupResource(), true),
			PathInventory: []string{"/auth/ldap/groups/{name}"},
		},
		"vault_ldap_secret_backend": {
			Resource:      UpdateSchemaResource(ldapSecretBackendResource(), true),
			PathInventory: []string{"/ldap/config"},
		},
		"vault_ldap_secret_backend_static_role": {
			Resource:      UpdateSchemaResource(ldapSecretBackendStaticRoleResource(), true),
			PathInventory: []string{"/ldap/static-role/{name}"},
		},
		"vault_ldap_secret_backend_dynamic_role": {
			Resource:      UpdateSchemaResource(ldapSecretBackendDynamicRoleResource(), true),
			PathInventory: []string{"/ldap/role/{name}"},
		},
		"vault_ldap_secret_backend_library_set": {
			Resource:      UpdateSchemaResource(ldapSecretBackendLibrarySetResource(), true),
			PathInventory: []string{"/ldap/library/{name}"},
		},
		"vault_nomad_secret_backend": {
			Resource: UpdateSchemaResource(nomadSecretAccessBackendResource(), true),
			PathInventory: []string{
				"/nomad",
				"/nomad/config/access",
				"/nomad/config/lease",
			},
		},
		"vault_nomad_secret_role": {
			Resource:      UpdateSchemaResource(nomadSecretBackendRoleResource(), true),
			PathInventory: []string{"/nomad/role/{role}"},
		},
		"vault_policy": {
			Resource:      UpdateSchemaResource(policyResource(), true),
			PathInventory: []string{"/sys/policy/{name}"},
		},
		"vault_egp_policy": {
			Resource:       UpdateSchemaResource(egpPolicyResource(), true),
			PathInventory:  []string{"/sys/policies/egp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_rgp_policy": {
			Resource:       UpdateSchemaResource(rgpPolicyResource(), true),
			PathInventory:  []string{"/sys/policies/rgp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mfa_duo": {
			Resource:       UpdateSchemaResource(mfaDuoResource(), true),
			PathInventory:  []string{"/sys/mfa/method/duo/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mfa_okta": {
			Resource:       UpdateSchemaResource(mfaOktaResource(), true),
			PathInventory:  []string{"/sys/mfa/method/okta/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mfa_totp": {
			Resource:       UpdateSchemaResource(mfaTOTPResource(), true),
			PathInventory:  []string{"/sys/mfa/method/totp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mfa_pingid": {
			Resource:       UpdateSchemaResource(mfaPingIDResource(), true),
			PathInventory:  []string{"/sys/mfa/method/totp/{name}"},
			EnterpriseOnly: true,
		},
		"vault_mount": {
			Resource:      UpdateSchemaResource(MountResource(), true),
			PathInventory: []string{"/sys/mounts/{path}"},
		},
		"vault_namespace": {
			Resource:       UpdateSchemaResource(namespaceResource(), true),
			PathInventory:  []string{"/sys/namespaces/{path}"},
			EnterpriseOnly: true,
		},
		"vault_audit": {
			Resource:      UpdateSchemaResource(auditResource(), true),
			PathInventory: []string{"/sys/audit/{path}"},
		},
		"vault_audit_request_header": {
			Resource:      UpdateSchemaResource(auditRequestHeaderResource(), true),
			PathInventory: []string{"/sys/config/auditing/request-headers/{path}"},
		},
		"vault_ssh_secret_backend_ca": {
			Resource:      UpdateSchemaResource(sshSecretBackendCAResource(), true),
			PathInventory: []string{"/ssh/config/ca"},
		},
		"vault_ssh_secret_backend_role": {
			Resource:      UpdateSchemaResource(sshSecretBackendRoleResource(), true),
			PathInventory: []string{"/ssh/roles/{role}"},
		},
		"vault_identity_entity": {
			Resource:      UpdateSchemaResource(identityEntityResource(), true),
			PathInventory: []string{"/identity/entity"},
		},
		"vault_identity_entity_alias": {
			Resource:      UpdateSchemaResource(identityEntityAliasResource(), true),
			PathInventory: []string{"/identity/entity-alias"},
		},
		"vault_identity_entity_policies": {
			Resource:      UpdateSchemaResource(identityEntityPoliciesResource(), true),
			PathInventory: []string{"/identity/lookup/entity"},
		},
		"vault_identity_group": {
			Resource:      UpdateSchemaResource(identityGroupResource(), true),
			PathInventory: []string{"/identity/group"},
		},
		"vault_identity_group_alias": {
			Resource:      UpdateSchemaResource(identityGroupAliasResource(), true),
			PathInventory: []string{"/identity/group-alias"},
		},
		"vault_identity_group_member_entity_ids": {
			Resource:      UpdateSchemaResource(identityGroupMemberEntityIdsResource(), true),
			PathInventory: []string{"/identity/group/id/{id}"},
		},
		"vault_identity_group_member_group_ids": {
			Resource:      UpdateSchemaResource(identityGroupMemberGroupIdsResource(), true),
			PathInventory: []string{"/identity/group/id/{id}"},
		},
		"vault_identity_group_policies": {
			Resource:      UpdateSchemaResource(identityGroupPoliciesResource(), true),
			PathInventory: []string{"/identity/lookup/group"},
		},
		"vault_identity_oidc": {
			Resource:      UpdateSchemaResource(identityOidc(), true),
			PathInventory: []string{"/identity/oidc/config"},
		},
		"vault_identity_oidc_key": {
			Resource:      UpdateSchemaResource(identityOidcKey(), true),
			PathInventory: []string{"/identity/oidc/key/{name}"},
		},
		"vault_identity_oidc_key_allowed_client_id": {
			Resource:      UpdateSchemaResource(identityOidcKeyAllowedClientId(), true),
			PathInventory: []string{"/identity/oidc/key/{name}"},
		},
		"vault_identity_oidc_role": {
			Resource:      UpdateSchemaResource(identityOidcRole(), true),
			PathInventory: []string{"/identity/oidc/role/{name}"},
		},
		"vault_rabbitmq_secret_backend": {
			Resource: UpdateSchemaResource(rabbitMQSecretBackendResource(), true),
			PathInventory: []string{
				"/rabbitmq/config/connection",
				"/rabbitmq/config/lease",
			},
		},
		"vault_rabbitmq_secret_backend_role": {
			Resource:      UpdateSchemaResource(rabbitMQSecretBackendRoleResource(), true),
			PathInventory: []string{"/rabbitmq/roles/{name}"},
		},
		"vault_password_policy": {
			Resource:      UpdateSchemaResource(passwordPolicyResource(), true),
			PathInventory: []string{"/sys/policy/password/{name}"},
		},
		"vault_pki_secret_backend_cert": {
			Resource:      UpdateSchemaResource(pkiSecretBackendCertResource(), true),
			PathInventory: []string{"/pki/issue/{role}"},
		},
		"vault_pki_secret_backend_crl_config": {
			Resource:      UpdateSchemaResource(pkiSecretBackendCrlConfigResource(), true),
			PathInventory: []string{"/pki/config/crl"},
		},
		"vault_pki_secret_backend_config_ca": {
			Resource:      UpdateSchemaResource(pkiSecretBackendConfigCAResource(), true),
			PathInventory: []string{"/pki/config/ca"},
		},
		"vault_pki_secret_backend_config_urls": {
			Resource:      UpdateSchemaResource(pkiSecretBackendConfigUrlsResource(), true),
			PathInventory: []string{"/pki/config/urls"},
		},
		"vault_pki_secret_backend_intermediate_cert_request": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIntermediateCertRequestResource(), true),
			PathInventory: []string{"/pki/intermediate/generate/{exported}"},
		},
		"vault_pki_secret_backend_intermediate_set_signed": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIntermediateSetSignedResource(), true),
			PathInventory: []string{"/pki/intermediate/set-signed"},
		},
		"vault_pki_secret_backend_role": {
			Resource:      UpdateSchemaResource(pkiSecretBackendRoleResource(), true),
			PathInventory: []string{"/pki/roles/{name}"},
		},
		"vault_pki_secret_backend_root_cert": {
			Resource:      UpdateSchemaResource(pkiSecretBackendRootCertResource(), true),
			PathInventory: []string{"/pki/root/generate/{exported}"},
		},
		"vault_pki_secret_backend_root_sign_intermediate": {
			Resource:      UpdateSchemaResource(pkiSecretBackendRootSignIntermediateResource(), true),
			PathInventory: []string{"/pki/root/sign-intermediate"},
		},
		"vault_pki_secret_backend_sign": {
			Resource:      UpdateSchemaResource(pkiSecretBackendSignResource(), true),
			PathInventory: []string{"/pki/sign/{role}"},
		},
		"vault_pki_secret_backend_key": {
			Resource:      UpdateSchemaResource(pkiSecretBackendKeyResource(), true),
			PathInventory: []string{"/pki/key/{key_id}"},
		},
		"vault_pki_secret_backend_issuer": {
			Resource:      UpdateSchemaResource(pkiSecretBackendIssuerResource(), true),
			PathInventory: []string{"/pki/issuer/{issuer_ref}"},
		},
		"vault_pki_secret_backend_config_issuers": {
			Resource:      UpdateSchemaResource(pkiSecretBackendConfigIssuers(), true),
			PathInventory: []string{"/pki/config/issuers"},
		},
		"vault_quota_lease_count": {
			Resource:      UpdateSchemaResource(quotaLeaseCountResource(), true),
			PathInventory: []string{"/sys/quotas/lease-count/{name}"},
		},
		"vault_quota_rate_limit": {
			Resource:      UpdateSchemaResource(quotaRateLimitResource(), true),
			PathInventory: []string{"/sys/quotas/rate-limit/{name}"},
		},
		"vault_terraform_cloud_secret_backend": {
			Resource:      UpdateSchemaResource(terraformCloudSecretBackendResource(), true),
			PathInventory: []string{"/terraform/config"},
		},
		"vault_terraform_cloud_secret_creds": {
			Resource:      UpdateSchemaResource(terraformCloudSecretCredsResource(), true),
			PathInventory: []string{"/terraform/creds/{role}"},
		},
		"vault_terraform_cloud_secret_role": {
			Resource:      UpdateSchemaResource(terraformCloudSecretRoleResource(), true),
			PathInventory: []string{"/terraform/role/{name}"},
		},
		"vault_transit_secret_backend_key": {
			Resource:      UpdateSchemaResource(transitSecretBackendKeyResource(), true),
			PathInventory: []string{"/transit/keys/{name}"},
		},
		"vault_transit_secret_cache_config": {
			Resource:      UpdateSchemaResource(transitSecretBackendCacheConfig(), true),
			PathInventory: []string{"/transit/cache-config"},
		},
		"vault_raft_snapshot_agent_config": {
			Resource:      UpdateSchemaResource(raftSnapshotAgentConfigResource(), true),
			PathInventory: []string{"/sys/storage/raft/snapshot-auto/config/{name}"},
		},
		"vault_raft_autopilot": {
			Resource:      UpdateSchemaResource(raftAutopilotConfigResource(), true),
			PathInventory: []string{"/sys/storage/raft/autopilot/configuration"},
		},
		"vault_kmip_secret_backend": {
			Resource:      UpdateSchemaResource(kmipSecretBackendResource(), true),
			PathInventory: []string{"/kmip/config"},
		},
		"vault_kmip_secret_scope": {
			Resource:      UpdateSchemaResource(kmipSecretScopeResource(), true),
			PathInventory: []string{"/kmip/scope/{scope}"},
		},
		"vault_kmip_secret_role": {
			Resource:      UpdateSchemaResource(kmipSecretRoleResource(), true),
			PathInventory: []string{"/kmip/scope/{scope}/role/{role}"},
		},
		"vault_mongodbatlas_secret_backend": {
			Resource:      UpdateSchemaResource(mongodbAtlasSecretBackendResource(), true),
			PathInventory: []string{"/mongodbatlas/config"},
		},
		"vault_mongodbatlas_secret_role": {
			Resource:      UpdateSchemaResource(mongodbAtlasSecretRoleResource(), true),
			PathInventory: []string{"/mongodbatlas/roles/{name}"},
		},
		"vault_identity_oidc_scope": {
			Resource:      UpdateSchemaResource(identityOIDCScopeResource(), true),
			PathInventory: []string{"/identity/oidc/scope/{scope}"},
		},
		"vault_identity_oidc_assignment": {
			Resource:      UpdateSchemaResource(identityOIDCAssignmentResource(), true),
			PathInventory: []string{"/identity/oidc/assignment/{name}"},
		},
		"vault_identity_oidc_client": {
			Resource:      UpdateSchemaResource(identityOIDCClientResource(), true),
			PathInventory: []string{"/identity/oidc/client/{name}"},
		},
		"vault_identity_oidc_provider": {
			Resource:      UpdateSchemaResource(identityOIDCProviderResource(), true),
			PathInventory: []string{"/identity/oidc/provider/{name}"},
		},
		"vault_kv_secret_backend_v2": {
			Resource:      UpdateSchemaResource(kvSecretBackendV2Resource(), true),
			PathInventory: []string{"/secret/data/{path}"},
		},
		"vault_kv_secret": {
			Resource:      UpdateSchemaResource(kvSecretResource("vault_kv_secret"), true),
			PathInventory: []string{"/secret/{path}"},
		},
		"vault_kv_secret_v2": {
			Resource:      UpdateSchemaResource(kvSecretV2Resource("vault_kv_secret_v2"), true),
			PathInventory: []string{"/secret/data/{path}"},
		},
		"vault_kubernetes_secret_backend": {
			Resource:      UpdateSchemaResource(kubernetesSecretBackendResource(), true),
			PathInventory: []string{"/kubernetes/config"},
		},
		"vault_kubernetes_secret_backend_role": {
			Resource:      UpdateSchemaResource(kubernetesSecretBackendRoleResource(), true),
			PathInventory: []string{"/kubernetes/roles/{name}"},
		},
		"vault_managed_keys": {
			Resource:      UpdateSchemaResource(managedKeysResource(), true),
			PathInventory: []string{"/sys/managed-keys/{type}/{name}"},
		},
	}
)

func UpdateSchemaResource(r *schema.Resource, writable bool) *schema.Resource {
	provider.MustAddSchema(r, provider.GetNamespaceSchema())

	// only add customize diff to resources supporting namespaces
	if writable {
		r.CustomizeDiff = provider.NamespacePathCustomizeDiffFunc()
	}

	return r
}
