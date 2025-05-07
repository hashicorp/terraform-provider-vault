## Unreleased

## 4.8.0 (Apr 23, 2025)

FEATURES:

* Add support for `recursive` search in `data_vault_namespaces` [#2408](https://github.com/hashicorp/terraform-provider-vault/pull/2408)
* Add support for `subscribe_event_types` in `data_source_policy_document` [#2445](https://github.com/hashicorp/terraform-provider-vault/pull/2445)
* Add support for `explicit_max_ttl` in `vault_azure_secret_backend_role` resources. Requires Vault 1.18+ ([#2438](https://github.com/hashicorp/terraform-provider-vault/pull/2438)).

BUGS:

* Fix credential validation failures in `vault_azure_access_credentials` data source caused by Azure RBAC propagation delays using `azure_groups` [#2437](https://github.com/hashicorp/terraform-provider-vault/pull/2437)

## 4.7.0 (Mar 12, 2025)

FEATURES:

* Update `vault_pki_secret_backend_root_cert` and `vault_pki_secret_backend_root_sign_intermediate` to support the new fields for the name constraints extension. Requires Vault 1.19+ ([#2396](https://github.com/hashicorp/terraform-provider-vault/pull/2396)).
* Update `vault_pki_secret_backend_issuer` resource with the new issuer configuration fields to control certificate verification. Requires Vault Enterprise 1.19+ ([#2400](https://github.com/hashicorp/terraform-provider-vault/pull/2400)).
* Add support for certificate revocation with `revoke_with_key` in `vault_pki_secret_backend_cert` ([#2242](https://github.com/hashicorp/terraform-provider-vault/pull/2242))
* Add support for signature_bits field to `vault_pki_secret_backend_role`, `vault_pki_secret_backend_root_cert`, `vault_pki_secret_backend_root_sign_intermediate` and `vault_pki_secret_backend_intermediate_cert_request` ([#2401])(https://github.com/hashicorp/terraform-provider-vault/pull/2401)
* Add support for key_usage and serial_number to `vault_pki_secret_backend_intermediate_cert_request` ([#2404])(https://github.com/hashicorp/terraform-provider-vault/pull/2404)
* Add support for `skip_import_rotation` in `vault_database_secret_backend_static_role`. Requires Vault Enterprise 1.18.5+ ([#2386](https://github.com/hashicorp/terraform-provider-vault/pull/2386)).
* Add support for `not_after` in `vault_pki_secret_backend_cert`, `vault_pki_secret_backend_role`, `vault_pki_secret_backend_root_cert`, `vault_pki_secret_backend_root_sign_intermediate`, and `vault_pki_secret_backend_sign` ([#2385](https://github.com/hashicorp/terraform-provider-vault/pull/2385)). 
* Update `vault_pki_secret_backend_config_acme` to support the `max_ttl` field. [#2411](https://github.com/hashicorp/terraform-provider-vault/pull/2411)
* Add new data source `vault_ssh_secret_backend_sign`. ([#2409](https://github.com/hashicorp/terraform-provider-vault/pull/2409))
* Add support for `disabled_validations` in `vault_pki_secret_backend_config_cmpv2` [#2412](https://github.com/hashicorp/terraform-provider-vault/pull/2412)
* Add `credential_type` and `credential_config` to `database_secret_backend_static_role` to support features like rsa keys for Snowflake DB engines with static roles [#2384](https://github.com/hashicorp/terraform-provider-vault/pull/2384)
* Add support for missing parameters to `vault_pki_secret_backend_root_sign_intermediate`: `not_before_duration`, `skid` and `use_pss` [#2417](https://github.com/hashicorp/terraform-provider-vault/pull/2417)
* Add support for `use_pss`, `no_store_metadata`, and `serial_number_source` to `vault_pki_secret_backend_role` [#2420](https://github.com/hashicorp/terraform-provider-vault/pull/2420)
* Add support for Transit `sign` and `verify` endpoints ([#2418](https://github.com/hashicorp/terraform-provider-vault/pull/2418))
* Add new data source `vault_pki_secret_backend_cert_metadata` and support for `cert_metadata` in `vault_pki_secret_backend_cert` and `vault_pki_secret_backend_sign` [#2422](https://github.com/hashicorp/terraform-provider-vault/pull/2422)
* Add support for `max_crl_entries` in `vault_pki_secret_backend_crl_config` [#2423](https://github.com/hashicorp/terraform-provider-vault/pull/2423)
* Add support for new Automated Root Rotation parameters in several plugins. Requires Vault Enterprise 1.19.0+.
  * AWS Auth/Secrets ([#2414](https://github.com/hashicorp/terraform-provider-vault/pull/2414))
  * Azure Auth/Secrets ([#2428](https://github.com/hashicorp/terraform-provider-vault/pull/2428))
  * DB Secrets ([#2414](https://github.com/hashicorp/terraform-provider-vault/pull/2414)).
  * LDAP Auth/Secrets ([#2428](https://github.com/hashicorp/terraform-provider-vault/pull/2428))
  * GCP Auth/Secrets ([#2427](https://github.com/hashicorp/terraform-provider-vault/pull/2427))
* Add new resource `vault_pki_secret_backend_config_auto_tidy` to set PKI automatic tidy configuration [#1934](https://github.com/hashicorp/terraform-provider-vault/pull/1934)
* Add support for cross-account management of static roles in AWS Secrets: ([#2413](https://github.com/hashicorp/terraform-provider-vault/pull/2413))

BUGS:

* Do not panic on Vault PKI roles without the cn_validations field: ([#2398](https://github.com/hashicorp/terraform-provider-vault/pull/2398))

IMPROVEMENTS:

* Update pki_secret_backend_crl_config to be more resilent to unknown response fields ([#2429](https://github.com/hashicorp/terraform-provider-vault/pull/2429))

## 4.6.0 (Jan 15, 2025)

FEATURES:

* Update `vault_database_secret_backend_connection`to support `password_authentication` for PostgreSQL, allowing to encrypt password before being passed to PostgreSQL ([#2371](https://github.com/hashicorp/terraform-provider-vault/pull/2371))
* Add support for `external_id` field for the `vault_aws_auth_backend_sts_role` resource ([#2370](https://github.com/hashicorp/terraform-provider-vault/pull/2370))
* Add support for ACME configuration with the `vault_pki_secret_backend_config_acme` resource. Requires Vault 1.14+ ([#2157](https://github.com/hashicorp/terraform-provider-vault/pull/2157)).
* Update `vault_pki_secret_backend_role` to support the `cn_validations` role field ([#1820](https://github.com/hashicorp/terraform-provider-vault/pull/1820)).
* Add new resource `vault_pki_secret_backend_acme_eab` to manage PKI ACME external account binding tokens. Requires Vault 1.14+. ([#2367](https://github.com/hashicorp/terraform-provider-vault/pull/2367))
* Add new data source and resource `vault_pki_secret_backend_config_cmpv2`. Requires Vault 1.18+. *Available only for Vault Enterprise* ([#2330](https://github.com/hashicorp/terraform-provider-vault/pull/2330))

IMPROVEMENTS:

* Support the event `subscribe` policy capability for `vault_policy_document` data source ([#2293](https://github.com/hashicorp/terraform-provider-vault/pull/2293))

## 4.5.0 (Nov 19, 2024)

FEATURES:

* Update `vault_database_secret_backend_connection` to support inline TLS config for PostgreSQL ([#2339](https://github.com/hashicorp/terraform-provider-vault/pull/2339))
* Update `vault_database_secret_backend_connection` to support skip_verification config for Cassandra ([#2346](https://github.com/hashicorp/terraform-provider-vault/pull/2346))
* Update `vault_approle_auth_backend_role_secret_id` to support `num_uses` and `ttl` fields ([#2345](https://github.com/hashicorp/terraform-provider-vault/pull/2345))
* Add support for `allow_empty_principals` field for the `vault_ssh_secret_backend_role` resource ([#2354](https://github.com/hashicorp/terraform-provider-vault/pull/2354))
* Update `vault_gcp_secret_impersonated_account` to support setting `ttl` ([#2318](https://github.com/hashicorp/terraform-provider-vault/pull/2318))
* Add support for `connection_timeout` field for the `vault_ldap_auth_backend` resource ([#2358](https://github.com/hashicorp/terraform-provider-vault/pull/2358))
* Add support for Rootless Configuration for Static Roles to Postgres DB ([#2341](https://github.com/hashicorp/terraform-provider-vault/pull/2341))
* Add support for `use_annotations_as_alias_metadata` field for the `vault_kubernetes_auth_backend_config` resource ([#2226](https://github.com/hashicorp/terraform-provider-vault/pull/2226))

BUGS:

* Remove consul secret backend role from state if not found on vault: ([#2321](https://github.com/hashicorp/terraform-provider-vault/pull/2321))

## 4.4.0 (Aug 7, 2024)

FEATURES:

* Update `vault_aws_secret_backend_role` to support setting `session_tags` and `external_id` ([#2290](https://github.com/hashicorp/terraform-provider-vault/pull/2290))

BUGS:

* fix `vault_ssh_secret_backend_ca` where a schema change forced the resource to be replaced ([#2308](https://github.com/hashicorp/terraform-provider-vault/pull/2308))
* fix a bug where a read on non-existent auth or secret mount resulted in an error that prevented the provider from completing successfully ([#2289](https://github.com/hashicorp/terraform-provider-vault/pull/2289))

## 4.3.0 (Jun 17, 2024)

FEATURES:
* Add support for `iam_tags` in `vault_aws_secret_backend_role` ([#2231](https://github.com/hashicorp/terraform-provider-vault/pull/2231)).
* Add support for `inheritable` on `vault_quota_rate_limit` and `vault_quota_lease_count`. Requires Vault 1.15+.: ([#2133](https://github.com/hashicorp/terraform-provider-vault/pull/2133)).
* Add support for new WIF fields in `vault_gcp_secret_backend`. Requires Vault 1.17+. *Available only for Vault Enterprise* ([#2249](https://github.com/hashicorp/terraform-provider-vault/pull/2249)).
* Add support for new WIF fields in `vault_azure_secret_backend`. Requires Vault 1.17+. *Available only for Vault Enterprise* ([#2250](https://github.com/hashicorp/terraform-provider-vault/pull/2250))
* Add support for new WIF fields in `vault_aws_auth_backend_client`. Requires Vault 1.17+. *Available only for Vault Enterprise* ([#2243](https://github.com/hashicorp/terraform-provider-vault/pull/2243)).
* Add support for new WIF fields in `vault_gcp_auth_backend` ([#2256](https://github.com/hashicorp/terraform-provider-vault/pull/2256))
* Add support for new WIF fields in `vault_azure_auth_backend_config`. Requires Vault 1.17+. *Available only for Vault Enterprise* ([#2254](https://github.com/hashicorp/terraform-provider-vault/pull/2254)).
* Add new data source and resource `vault_pki_secret_backend_config_est`. Requires Vault 1.16+. *Available only for Vault Enterprise* ([#2246](https://github.com/hashicorp/terraform-provider-vault/pull/2246))
* Support missing token parameters on `vault_okta_auth_backend` resource: ([#2210](https://github.com/hashicorp/terraform-provider-vault/pull/2210))
* Add support for `max_retries` in `vault_aws_auth_backend_client`: ([#2270](https://github.com/hashicorp/terraform-provider-vault/pull/2270))
* Add new resources `vault_plugin` and `vault_plugin_pinned_version`: ([#2159](https://github.com/hashicorp/terraform-provider-vault/pull/2159))
* Add `key_type` and `key_bits` to `vault_ssh_secret_backend_ca`: ([#1454](https://github.com/hashicorp/terraform-provider-vault/pull/1454))

IMPROVEMENTS:
* return a useful error when delete fails for the `vault_jwt_auth_backend_role` resource: ([#2232](https://github.com/hashicorp/terraform-provider-vault/pull/2232))
BUGS:
* Remove dependency on `github.com/hashicorp/vault` package: ([#2251](https://github.com/hashicorp/terraform-provider-vault/pull/2251))
* Add missing `custom_tags` and `secret_name_template` fields to `vault_secrets_sync_azure_destination` resource ([#2247](https://github.com/hashicorp/terraform-provider-vault/pull/2247))
* Fix handling of 0 value within field `max_path_length` in `vault_pki_secret_backend_root_cert` and `vault_pki_secret_backend_root_sign_intermediate` resources ([#2253](https://github.com/hashicorp/terraform-provider-vault/pull/2253))

## 4.2.0 (Mar 27, 2024)

FEATURES:
* Add `granularity` to Secrets Sync destination resources. Requires Vault 1.16+ Enterprise. ([#2202](https://github.com/hashicorp/terraform-provider-vault/pull/2202))
* Add support for `allowed_kubernetes_namespace_selector` in `vault_kubernetes_secret_backend_role` ([#2180](https://github.com/hashicorp/terraform-provider-vault/pull/2180)).
* Add new data source `vault_namespace`. Requires Vault Enterprise: ([#2208](https://github.com/hashicorp/terraform-provider-vault/pull/2208)).
* Add new data source `vault_namespaces`. Requires Vault Enterprise: ([#2212](https://github.com/hashicorp/terraform-provider-vault/pull/2212)).

IMPROVEMENTS:
* Enable Secrets Sync Association resource to track sync status across all subkeys of a secret. Requires Vault 1.16+ Enterprise. ([#2202](https://github.com/hashicorp/terraform-provider-vault/pull/2202))

BUGS:
* fix `vault_approle_auth_backend_role_secret_id` regression to handle 404 errors ([#2204](https://github.com/hashicorp/terraform-provider-vault/pull/2204))
* fix `vault_kv_secret` and `vault_kv_secret_v2` failure to update secret data modified outside terraform ([#2207](https://github.com/hashicorp/terraform-provider-vault/pull/2207))
* fix `vault_kv_secret_v2` failing on imported resource when data_json should be ignored ([#2207](https://github.com/hashicorp/terraform-provider-vault/pull/2207))

## 4.1.0 (Mar 20, 2024)

CHANGES TO VAULT POLICY REQUIREMENTS:

* **Important**: This release requires read policies to be set at the path level for mount metadata.
The v4.0.0 release required read permissions at `sys/auth/:path` which was a
sudo endpoint. The v4.1.0 release changed that to instead require permissions
at the `sys/mounts/auth/:path` level and sudo is no longer required. Please
refer to the details in the [Terraform Vault Provider 4.0.0 Upgrade Guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/version_4_upgrade).

FEATURES:
* Add new resource `vault_config_ui_custom_message`. Requires Vault 1.16+ Enterprise: ([#2154](https://github.com/hashicorp/terraform-provider-vault/pull/2154)).

IMPROVEMENTS:
* do not require sudo permissions for auth read operations ([#2198](https://github.com/hashicorp/terraform-provider-vault/pull/2198))

BUGS:
* fix `vault_azure_access_credentials` to default to Azure Public Cloud ([#2190](https://github.com/hashicorp/terraform-provider-vault/pull/2190))

## 4.0.0 (Mar 13, 2024)

**Important**: This release requires read policies to be set at the path level for mount metadata.
For example, instead of permissions at `sys/auth` you must set permissions at
the `sys/auth/:path` level. Please refer to the details in the
[Terraform Vault Provider 4.0.0 Upgrade Guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/version_4_upgrade).

FEATURES:
* Add support for PKI Secrets Engine cluster configuration with the `vault_pki_secret_backend_config_cluster` resource. Requires Vault 1.13+ ([#1949](https://github.com/hashicorp/terraform-provider-vault/pull/1949)).
* Add support to `enable_templating` in `vault_pki_secret_backend_config_urls` ([#2147](https://github.com/hashicorp/terraform-provider-vault/pull/2147)).
* Add support for `skip_import_rotation` and `skip_static_role_import_rotation` in `ldap_secret_backend_static_role` and `ldap_secret_backend` respectively. Requires Vault 1.16+ ([#2128](https://github.com/hashicorp/terraform-provider-vault/pull/2128)).
* Improve logging to track full API exchanges between the provider and Vault ([#2139](https://github.com/hashicorp/terraform-provider-vault/pull/2139))
* Add new `vault_plugin` and `vault_plugin_pinned_version` resources for managing external plugins ([#2159](https://github.com/hashicorp/terraform-provider-vault/pull/2159))

IMPROVEMENTS:
* Improve performance of READ operations across many resources: ([#2145](https://github.com/hashicorp/terraform-provider-vault/pull/2145)), ([#2152](https://github.com/hashicorp/terraform-provider-vault/pull/2152))
* Add the metadata `version` in returned values for `vault_kv_secret_v2` data source: ([#2095](https://github.com/hashicorp/terraform-provider-vault/pull/2095))
* Add new secret sync destination fields: ([#2150](https://github.com/hashicorp/terraform-provider-vault/pull/2150))

BUGS:
* Handle graceful destruction of resources when approle is deleted out-of-band ([#2142](https://github.com/hashicorp/terraform-provider-vault/pull/2142)).
* Ensure errors are returned on read operations for `vault_ldap_secret_backend_static_role`, `vault_ldap_secret_backend_library_set`, and `vault_ldap_secret_backend_static_role` ([#2156](https://github.com/hashicorp/terraform-provider-vault/pull/2156)).
* Ensure proper use of issuer endpoints for root sign intermediate resource: ([#2160](https://github.com/hashicorp/terraform-provider-vault/pull/2160))
* Fix issuer data overwrites on updates: ([#2186](https://github.com/hashicorp/terraform-provider-vault/pull/2186))

## 3.25.0 (Feb 14, 2024)

FEATURES:
* Add destination and association resources to support Secrets Sync. Requires Vault 1.16+ ([#2098](https://github.com/hashicorp/terraform-provider-vault/pull/2098)).
* Add support for configuration of plugin WIF to the AWS Secret Backend. Requires Vault 1.16+ ([#2138](https://github.com/hashicorp/terraform-provider-vault/pull/2138)).
* Add support for Oracle database plugin configuration options `split_statements` and `disconnect_sessions`: ([#2085](https://github.com/hashicorp/terraform-provider-vault/pull/2085))

IMPROVEMENTS:
* Add an API client lock to the `vault_identity_group_alias` resource: ([#2140](https://github.com/hashicorp/terraform-provider-vault/pull/2140))

## 3.24.0 (Jan 17, 2024)

FEATURES:
* Add support for `ext_key_usage_oids` in `vault_pki_secret_backend_role` ([#2108](https://github.com/hashicorp/terraform-provider-vault/pull/2108))
* Adds support to `vault_gcp_auth_backend` for common backend tune parameters ([#1997](https://github.com/terraform-providers/terraform-provider-vault/pull/1997)).
* Adds support to `vault_azure_secret_backend_role` for `sign_in_audience` and `tags`. Requires Vault 1.16+. ([#2101](https://github.com/terraform-providers/terraform-provider-vault/pull/2101)).

BUGS:
* fix `vault_kv_secret_v2` drift when "data" is in secret name/path ([#2104](https://github.com/hashicorp/terraform-provider-vault/pull/2104))
* fix `vault_database_secret_backend_connection`: allow mysql_rds,mysql_aurora,mysql_legacy options of vault_database_secret_backend_connection terraform resource to allow specifying tls_ca and tls_certificate_key ([#2106](https://github.com/hashicorp/terraform-provider-vault/pull/2106))
* Fix ignored `description` updates for `aws_secret_backend` resource ([#2057](https://github.com/hashicorp/terraform-provider-vault/pull/2057))

IMPROVEMENTS:
* Updated dependencies ([#2129](https://github.com/hashicorp/terraform-provider-vault/pull/2129)):
   * `cloud.google.com/go/iam` v1.1.2 -> v1.1.5
   * `github.com/Azure/azure-sdk-for-go/sdk/azcore` v1.8.0 -> v1.9.1
   * `github.com/Azure/azure-sdk-for-go/sdk/azidentity` v1.4.0 -> v1.5.0
   * `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources` v1.1.1 -> v1.2.0
   * `github.com/aws/aws-sdk-go` v1.45.24 -> v1.49.22
   * `github.com/google/uuid` v1.3.1 -> v1.5.0
   * `github.com/hashicorp/go-hclog` v1.5.0 -> v1.6.2
   * `github.com/hashicorp/go-retryablehttp` v0.7.4 -> v0.7.5
   * `github.com/hashicorp/go-secure-stdlib/parseutil` v0.1.7 -> v0.1.8
   * `github.com/hashicorp/terraform-plugin-sdk/v2` v2.29.0 -> v2.31.0
   * `github.com/hashicorp/vault-plugin-auth-jwt` v0.17.0 -> v0.18.0
   * `github.com/hashicorp/vault/sdk` v0.10.0 -> v0.10.2
   * `golang.org/x/crypto` v0.14.0 -> v0.18.0
   * `golang.org/x/net` v0.15.0 -> v0.20.0
   * `golang.org/x/oauth2` v0.12.0 -> v0.16.0
   * `google.golang.org/api` v0.144.0 -> v0.156.0
   * `google.golang.org/genproto` v0.0.0-20231002182017-d307bd883b97 -> v0.0.0-20240116215550-a9fa1716bcac
   * `k8s.io/utils` v0.0.0-20230726121419-3b25d923346b -> v0.0.0-20240102154912-e7106e64919e

## 3.23.0 (Nov 15, 2023)

FEATURES:
* Add support for lazily authenticating to Vault: ([#2049](https://github.com/hashicorp/terraform-provider-vault/pull/2049))

BUGS:
* Fix `vault_identity_group` loses externally managed policies on updates when `external_policies = true` ([#2084](https://github.com/hashicorp/terraform-provider-vault/pull/2084))
* Fix regression in `vault_azure_access_credentials` where we returned prematurely on 401 responses:([#2086](https://github.com/hashicorp/terraform-provider-vault/pull/2086))

## 3.22.0 (Nov 1, 2023)

FEATURES:
* Add support for configuring SAML Auth resources ([#2053](https://github.com/hashicorp/terraform-provider-vault/pull/2053))
* Add support for `custom_metadata` on `vault_namespace`: ([#2033](https://github.com/hashicorp/terraform-provider-vault/pull/2033))
* Add support for `OCSP*` role fields for the cert auth resource: ([#2056](https://github.com/hashicorp/terraform-provider-vault/pull/2056))
* Add field `set_namespace_from_token` to Provider configuration ([#2070](https://github.com/hashicorp/terraform-provider-vault/pull/2070))
* Support authenticating to the root namespace from within an auth_login*: ([#2066](https://github.com/hashicorp/terraform-provider-vault/pull/2066))

BUGS:
* Fix panic when reading `client_secret` from a public oidc client ([#2048](https://github.com/hashicorp/terraform-provider-vault/pull/2048))
* Fix API request missing `roles` field for `mongodbatlas_secret_role` resource ([#2047](https://github.com/hashicorp/terraform-provider-vault/pull/2047))
* Fix bug when updating `vault_azure_secret_backend_role`: ([#2063](https://github.com/hashicorp/terraform-provider-vault/pull/2063))
* Fix audience string ordering for `auth_login_gcp` causing GCE auth to fail ([#2064](https://github.com/hashicorp/terraform-provider-vault/pull/2064))

IMPROVEMENTS:
* Updated dependencies: ([#2038](https://github.com/hashicorp/terraform-provider-vault/pull/2038))
   * `github.com/aws/aws-sdk-go` v1.44.106 -> v1.45.24
* Updated dependencies: ([#2050](https://github.com/hashicorp/terraform-provider-vault/pull/2050))
   * `github.com/Azure/azure-sdk-for-go/sdk/azcore` v0.22.0 -> v1.8.0
   * `github.com/Azure/azure-sdk-for-go/sdk/azidentity` v0.13.2 -> v1.4.0
   * `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources` v0.3.1 -> v1.1.1
   * `github.com/Azure/go-autorest/autorest` v0.11.29 removed

## 3.21.0 (Oct 9, 2023)

FEATURES:
* Add GCP CloudSQL support to Postgres, MySQL DB engines: ([#2012](https://github.com/hashicorp/terraform-provider-vault/pull/2012))
* Add support for DB Adv TTL Mgmt: ([#2011](https://github.com/hashicorp/terraform-provider-vault/pull/2011))
* Add support for setting `not_before_duration` argument on `vault_ssh_secret_backend_role`: ([#2019](https://github.com/hashicorp/terraform-provider-vault/pull/2019))
* Add support for `hmac` key type and key_size to `vault_transit_secret_backend_key`: ([#2034](https://github.com/hashicorp/terraform-provider-vault/pull/2034/))
* Add support for roles to both rate limit and lease count quotas: ([#1994](https://github.com/hashicorp/terraform-provider-vault/pull/1994))
* Add `allowed_email_sans` field to write and update functions of `vault_cert_auth_backend_role`: ([#1140](https://github.com/hashicorp/terraform-provider-vault/pull/1140))
* Add support for `local` parameter in aws secret engine: ([#2013](https://github.com/hashicorp/terraform-provider-vault/pull/2013))

BUGS:
* Fix duplicate timestamp and incorrect level messages: ([#2031](https://github.com/hashicorp/terraform-provider-vault/pull/2031))
* Fix panic when setting `key_usage` to an array of empty string and enable it to unset the key usage constraints: ([#2036](https://github.com/hashicorp/terraform-provider-vault/pull/2036))
* Add state migrator for `external_member_group_ids`  in Identity Group ([#2043](https://github.com/hashicorp/terraform-provider-vault/pull/2043))
* Fix drift detection for the kv-v2 secrets resource when `disable_read` is enabled: ([#2039](https://github.com/hashicorp/terraform-provider-vault/pull/2039))
* Add state migrator in secrets/auth backends for `disable_remount` parameter ([#2037](https://github.com/hashicorp/terraform-provider-vault/pull/2037))
* Fix failure when `auth_login` is specified and vault token is picked up from the runtime/execution environment: ([#2029](https://github.com/hashicorp/terraform-provider-vault/pull/2029))
* Remove logging of password key: ([#2044](https://github.com/hashicorp/terraform-provider-vault/pull/2044))

IMPROVEMENTS:
* Oracle DB engine enablement on HCP Vault: ([#2006](https://github.com/hashicorp/terraform-provider-vault/pull/2006))
* Ensure sensitive values are masked in `vault_approle_auth_backend_login` plan output ([#2008](https://github.com/hashicorp/terraform-provider-vault/pull/2008))
* Updated dependencies: ([#2038](https://github.com/hashicorp/terraform-provider-vault/pull/2038))
   * `cloud.google.com/go/compute` v1.10.0 removed
   * `cloud.google.com/go/compute/metadata` v0.2.3 added
   * `cloud.google.com/go/iam` v0.3.0 -> v1.1.2
   * `github.com/Azure/go-autorest/autorest` v0.11.24 -> v0.11.29
   * `github.com/cenkalti/backoff/v4` v4.1.2 -> v4.2.1
   * `github.com/coreos/pkg` v0.0.0-20180928190104-399ea9e2e55f -> v0.0.0-20230601102743-20bbbf26f4d8
   * `github.com/denisenkom/go-mssqldb` v0.12.0 -> v0.12.3
   * `github.com/go-sql-driver/mysql` v1.6.0 -> v1.7.1
   * `github.com/google/uuid` v1.3.0 -> v1.3.1
   * `github.com/gosimple/slug` v1.11.0 -> v1.13.1
   * `github.com/hashicorp/go-cty` v1.4.1-0.20200414143053-d3edf31b6320 -> v1.4.1-0.20200723130312-85980079f637
   * `github.com/hashicorp/go-retryablehttp` v0.7.1 -> v0.7.4
   * `github.com/hashicorp/terraform-plugin-sdk/v2` v2.16.0 -> v2.29.0
   * `github.com/hashicorp/vault-plugin-auth-jwt` v0.13.2-0.20221012184020-28cc68ee722b -> v0.17.0
   * `github.com/hashicorp/vault-plugin-auth-kerberos` v0.8.0 -> v0.10.1
   * `github.com/hashicorp/vault-plugin-auth-oci` v0.13.0-pre -> v0.14.2
   * `github.com/hashicorp/vault/api` v1.9.3-0.20230628215639-3ca33976762c -> v1.10.0
   * `github.com/hashicorp/vault/sdk` v0.6.0 -> v0.10.0
   * `github.com/jcmturner/gokrb5/v8` v8.4.2 -> v8.4.4
   * `golang.org/x/crypto` v0.6.0 -> v0.14.0
   * `golang.org/x/net` v0.7.0 -> v0.15.0
   * `golang.org/x/oauth2` v0.0.0-20221006150949-b44042a4b9c1 -> v0.12.0
   * `google.golang.org/api` v0.98.0 -> v0.144.0
   * `google.golang.org/genproto` v0.0.0-20221010155953-15ba04fc1c0e -> v0.0.0-20231002182017-d307bd883b97
   * `k8s.io/utils` v0.0.0-20220210201930-3a6ce19ff2f9 -> v0.0.0-20230726121419-3b25d923346b

## 3.20.1 (Sep 13, 2023)
IMPROVEMENTS:
* Update dependencies ([#1958](https://github.com/hashicorp/terraform-provider-vault/pull/1958))
  * github.com/hashicorp/go-secure-stdlib/awsutil `v0.1.6` -> `v0.2.3`
* Add `local` variable to `aws_secret_backend` resource, in order to mark the mount as non - replicated

BUGS:
* Update k8s-auth config to support unsetting the K8s CA Cert: ([#2005](https://github.com/hashicorp/terraform-provider-vault/pull/2005))

## 3.20.0 (Aug 30, 2023)
FEATURES:
* Add support for setting `permanently_delete` argument on `resource_azure_secret_backend_role`: ([#1958](https://github.com/hashicorp/terraform-provider-vault/pull/1958))
* Add `use_sts_region_from_client` to AWS Auth Config: ([#1963](https://github.com/hashicorp/terraform-provider-vault/pull/1963))
* Add accessor attribute for `vault_gcp_auth_backend` resource: ([#1980](https://github.com/hashicorp/terraform-provider-vault/pull/1980))

BUGS:
* Fixes a panic that can occur when Vault [lookup-self](https://developer.hashicorp.com/vault/api-docs/auth/token#lookup-a-token-self) API returns nil token info ([#1978](https://github.com/hashicorp/terraform-provider-vault/pull/1978))
* Resolve TF state for PKI Multi-Issuer workflows: ([#1973](https://github.com/hashicorp/terraform-provider-vault/pull/1973))
* Check the seal-status on the default namespace: ([#1967](https://github.com/hashicorp/terraform-provider-vault/pull/1967))

## 3.19.0 (Aug 2, 2023)
FEATURES:
* Add support for User ID configuration for PKI Secrets Engine: ([#1936](https://github.com/hashicorp/terraform-provider-vault/pull/1936))
* Add support for `use_sts_region_from_client` in `vault_aws_auth_backend_client` available in Vault v1.15.0+: ([#1963](https://github.com/hashicorp/terraform-provider-vault/pull/1963))

BUGS:
* auth/aws: enable namespace support for AWS backend config identity: ([#1961](https://github.com/hashicorp/terraform-provider-vault/pull/1961))
* Retry Write on kv-v2 config: ([#1955](https://github.com/hashicorp/terraform-provider-vault/pull/1955))
* Update `vault_identity_entity` to exclude policies from Vault request if `external_policies` is `true`: ([#1950](https://github.com/hashicorp/terraform-provider-vault/pull/1950))
* Bump Go version to fix macOS resolver issue: ([#1941](https://github.com/hashicorp/terraform-provider-vault/pull/1941))

## 3.18.0 (Jul 12, 2023)
FEATURES:
* Add support to set default issuers configuration for PKI Secrets Engine: ([#1937](https://github.com/hashicorp/terraform-provider-vault/pull/1937))
* Add new `auth_login_token_file` method: ([#1928](https://github.com/hashicorp/terraform-provider-vault/pull/1928))
* Update HTTP transport wrapper to support TLSConfig cloning: ([#1926](https://github.com/hashicorp/terraform-provider-vault/pull/1926))

BUGS:
* secrets/pki: fix server_flag being ignored: ([#1933](https://github.com/hashicorp/terraform-provider-vault/pull/1933))

## 3.17.0 (June 21, 2023)
FEATURES:
* Add support for multi-issuer functionality to PKI: ([#1910](https://github.com/hashicorp/terraform-provider-vault/pull/1910))
* Add x509 support to database roles: ([#1901](https://github.com/hashicorp/terraform-provider-vault/pull/1901))
* Add AWS Static Roles support: ([#1877](https://github.com/hashicorp/terraform-provider-vault/pull/1877))
* Add support for `max_page_size` in the `vault_ldap_auth_backend`: ([#1878](https://github.com/hashicorp/terraform-provider-vault/pull/1878))

BUGS:
* Fix DB Engine password overwrite for remaining databases: ([#1912](https://github.com/hashicorp/terraform-provider-vault/pull/1912))

## 3.16.0 (June 7, 2023)
FEATURES:
* Add support for LDAP secrets engine: ([#1859](https://github.com/hashicorp/terraform-provider-vault/pull/1859))
* Add new data source `vault_auth_backends`: ([#1827](https://github.com/hashicorp/terraform-provider-vault/pull/1827))
* Support allowed_domains_template on ssh_secret_backend_role. Fixes hashicorp#1675: ([#1676](https://github.com/hashicorp/terraform-provider-vault/pull/1676))

IMPROVEMENTS:
* Add support for retrying kv-v2 secret data writes: ([#1887](https://github.com/hashicorp/terraform-provider-vault/pull/1887))
* Add back support for deriving the provider namespace from the Vault token's: ([#1841](https://github.com/hashicorp/terraform-provider-vault/pull/1841))

BUGS:
* Fix DB engine password overwrite: ([#1876](https://github.com/hashicorp/terraform-provider-vault/pull/1876))
* azure/auth: fix config path parsing: ([#1871](https://github.com/hashicorp/terraform-provider-vault/pull/1871))

## 3.15.2 (May 3, 2023)
BUGS:
* Revert [#1830](https://github.com/hashicorp/terraform-provider-vault/pull/1830) which introduced a unexpected breaking change in the way authentication is done within a namespace: ([#1840](https://github.com/hashicorp/terraform-provider-vault/pull/1840))

## 3.15.1 (May 3, 2023)
BUGS:
* Ensure that the auth_login honours the provider's namespace: ([#1830](https://github.com/hashicorp/terraform-provider-vault/pull/1830))

## 3.15.0 (April 17, 2023)
FEATURES:
* Add support for MongoDB Atlas Secrets engine: ([#1816](https://github.com/hashicorp/terraform-provider-vault/pull/1816))

BUGS:
* Fix panic while importing namespaces: ([#1818](https://github.com/hashicorp/terraform-provider-vault/pull/1818))
* Avoid writing empty strings to Vault when creating PKCS managed keys: ([#1803](https://github.com/hashicorp/terraform-provider-vault/pull/1803))
* Fix possible panic with autopilot import: ([#1801](https://github.com/hashicorp/terraform-provider-vault/pull/1801))
* Ensure that the `qr_size` can be properly configured for MFA TOTP: ([#1750](https://github.com/hashicorp/terraform-provider-vault/pull/1750))

## 3.14.0 (March 15, 2023)
FEATURES:
* Add PKI Unified CRL parameters: ([#1789](https://github.com/hashicorp/terraform-provider-vault/pull/1789))
* Add resource for GCP impersonated account support: ([#1745](https://github.com/hashicorp/terraform-provider-vault/pull/1745))

BUGS:
* Add nil check for `IsEnterpriseSupported` util: ([#1787](https://github.com/hashicorp/terraform-provider-vault/pull/1787))
* Fix KV incorrect metadata path for prefixed mounts: ([#1781](https://github.com/hashicorp/terraform-provider-vault/pull/1781))

## 3.13.0 (February 17, 2023)
FEATURES:
* Add new resource for AWS Auth Backend config identity: ([#1724](https://github.com/hashicorp/terraform-provider-vault/pull/1724))
* Support `default_user_template` field on `vault_ssh_secret_backend_role`: ([#1725](https://github.com/hashicorp/terraform-provider-vault/pull/1725))

IMPROVEMENTS:
* Secrets from the AD, AWS, Azure & Nomad Secrets Engines are sensitive: ([#1726](https://github.com/hashicorp/terraform-provider-vault/pull/1726))
* Add enterprise check for new Raft Autopilot parameter: ([#1721](https://github.com/hashicorp/terraform-provider-vault/pull/1721))

BUGS:
* Fix KVV2 datasource upon retrieval of soft deleted secrets: ([#1760](https://github.com/hashicorp/terraform-provider-vault/pull/1760))
* Fix issue where removing optional fields in database secrets backend connection resource did not reset the fields to their default values: ([#1737](https://github.com/hashicorp/terraform-provider-vault/pull/1737))
* Fix construction of metadata path in KV V2 resource: ([#1722](https://github.com/hashicorp/terraform-provider-vault/pull/1722))

## 3.12.0 (January 5, 2023)
IMPROVEMENTS:
* Add support for importing the PKI CRL config: ([#1710](https://github.com/hashicorp/terraform-provider-vault/pull/1710))
* Ensure duplicate alias names are handled properly in LookupEntityAlias: ([#1708](https://github.com/hashicorp/terraform-provider-vault/pull/1708))
* Add support for a Raft Autopilot State datasource: ([#1705](https://github.com/hashicorp/terraform-provider-vault/pull/1705))
* Add support for adding metadata to a KV V2 Secret: ([#1687](https://github.com/hashicorp/terraform-provider-vault/pull/1687))
* Set AWS credentials sensitive: ([#1678](https://github.com/hashicorp/terraform-provider-vault/pull/1678))
* Set ForceNew on the path field of namespaces: ([#1713](https://github.com/hashicorp/terraform-provider-vault/pull/1713))

BUGS:
* Fix removed MSGraph param in Azure Secrets: ([#1682](https://github.com/hashicorp/terraform-provider-vault/pull/1682))
* Fix KV V2 data source when specifying a version: ([#1677](https://github.com/hashicorp/terraform-provider-vault/pull/1677))
* Ensure that `vault_kv_secret_backend_v2` mount is correctly imported: ([#1701](https://github.com/hashicorp/terraform-provider-vault/pull/1701))

## 3.11.0 (November 16, 2022)
IMPROVEMENTS:
* Add Basic Constraints attribute to vault_pki_secret_backend_intermediate_cert_request: ([#1661](https://github.com/hashicorp/terraform-provider-vault/pull/1661))
* Add Redis database secrets engine support: ([#1659](https://github.com/hashicorp/terraform-provider-vault/pull/1659))
* Add support for setting deletion_allowed on a transformation: ([#1650](https://github.com/hashicorp/terraform-provider-vault/pull/1650))

BUGS:
* Fix panic while importing MFA Duo resource: ([#1669](https://github.com/hashicorp/terraform-provider-vault/pull/1669))
* Fix GCP auth with service account credentials: ([#1648](https://github.com/hashicorp/terraform-provider-vault/pull/1648))

## 3.10.0 (October 26, 2022)
IMPROVEMENTS:
* Add support for externally managed Group Member IDs to Vault Identity Group: ([#1630](https://github.com/hashicorp/terraform-provider-vault/pull/1630))
* Support configuring vault version handling: ([#1646](https://github.com/hashicorp/terraform-provider-vault/pull/1646))

BUGS:
* Ensure that namespaced github auth mounts are destroyed: ([#1637](https://github.com/hashicorp/terraform-provider-vault/pull/1637))
* Ensure all AuthLogin instances are validated on call to Login(): ([#1631](https://github.com/hashicorp/terraform-provider-vault/pull/1631))

## 3.9.1 (October 06, 2022)
BUGS:
* Use the correct AWS login headers within auth_generic: ([#1625](https://github.com/hashicorp/terraform-provider-vault/pull/1625))
* Fix resource recreation following out-of-band changes in Vault: ([#1567](https://github.com/hashicorp/terraform-provider-vault/pull/1567))

## 3.9.0 (October 05, 2022)
IMPROVEMENTS:
* Add first-class Azure login support: ([#1617](https://github.com/hashicorp/terraform-provider-vault/pull/1617))
* Add first-class OIDC andJWT login support: ([#1615](https://github.com/hashicorp/terraform-provider-vault/pull/1615))
* Add first-class OCI login support: ([#1614](https://github.com/hashicorp/terraform-provider-vault/pull/1614))
* Add first-class Radius login support: ([#1609](https://github.com/hashicorp/terraform-provider-vault/pull/1609))
* Add first-class Kerberos login support: ([#1608](https://github.com/hashicorp/terraform-provider-vault/pull/1608))
* Add first-class GCP login support: ([#1607](https://github.com/hashicorp/terraform-provider-vault/pull/1607))
* Add first-class TLS certificates login support: ([#1605](https://github.com/hashicorp/terraform-provider-vault/pull/1605))
* Add first-class auth login config support for AWS: ([#1599](https://github.com/hashicorp/terraform-provider-vault/pull/1599)) ([#1618](https://github.com/hashicorp/terraform-provider-vault/pull/1618))
* Add support for login MFA resources: ([#1620](https://github.com/hashicorp/terraform-provider-vault/pull/1620))
* Add Managed Keys support: ([#1508](https://github.com/hashicorp/terraform-provider-vault/pull/1508))
* Add support to perform semantic version comparisons against Vault's server version: ([#1426](https://github.com/hashicorp/terraform-provider-vault/pull/1426))
* Add Mount Migration support to all secrets/auth backends: ([#1594](https://github.com/hashicorp/terraform-provider-vault/pull/1594))
* Use new semantic version checking for Consul secrets backend logic: ([#1593](https://github.com/hashicorp/terraform-provider-vault/pull/1593))
* Docs: Fix vault_kv_secret_backend_v2 delete_version_after example: ([#1602](https://github.com/hashicorp/terraform-provider-vault/pull/1602))
* Support creating Azure secret backend role by specifying the role_id: ([#1573](https://github.com/hashicorp/terraform-provider-vault/pull/1573))
* Add Redis ElastiCache database secrets engine support: ([#1596](https://github.com/hashicorp/terraform-provider-vault/pull/1596))
* vault_pki_secret_backend_cert: Report when renewal is pending: ([#1597](https://github.com/hashicorp/terraform-provider-vault/pull/1597))
* Accept data source values in the token field for Consul secrets backend: ([#1600](https://github.com/hashicorp/terraform-provider-vault/pull/1600))

BUGS:
* Fix erroneous persistent diff in the vault_token resource.: ([#1622](https://github.com/hashicorp/terraform-provider-vault/pull/1622))
* Fix data_source_azure_access_credentials US Government Cloud: ([#1590](https://github.com/hashicorp/terraform-provider-vault/pull/1590))
* Add kv-v2 write retry: ([#1579](https://github.com/hashicorp/terraform-provider-vault/pull/1579))

## 3.8.2 (August 11, 2022)
IMPROVEMENTS:
* Add bootstrap field to Consul backend resources: ([#1571](https://github.com/hashicorp/terraform-provider-vault/pull/1571))
* Add `data` field to KV data sources: ([#1577](https://github.com/hashicorp/terraform-provider-vault/pull/1577))

BUGS:
* fix: remove unnecessary nesting of secret data for KV-V1 secrets: ([#1570](https://github.com/hashicorp/terraform-provider-vault/pull/1570))

NOTES:
* `vault_kv_secret` no longer stores secrets in Vault under a nested `data` object.
  In versions 3.8.1 and below, the kv resource inadvertently nested the `value` under `data`.
  To remedy this please update any consumers of this KV and run a `terraform apply` to properly set the value.

## 3.8.1 (August 04, 2022)
IMPROVEMENTS:
* docs: Fix broken provider.namespace links: ([#1562](https://github.com/hashicorp/terraform-provider-vault/pull/1562))
* docs: Add Azure example for `r/raft_snapshot_agent_config`: ([#1534](https://github.com/hashicorp/terraform-provider-vault/pull/1534))
* docs: Document namespaced resource import: ([#1561](https://github.com/hashicorp/terraform-provider-vault/pull/1561))
* docs: Add more visible note that `d/aws_access_credentials` cannot be renewed: ([#1464](https://github.com/hashicorp/terraform-provider-vault/pull/1464))

BUGS:
* fix: Persist namespace to state on resource import: ([#1563](https://github.com/hashicorp/terraform-provider-vault/pull/1563))
* fix: Update all transform resources with namespace support: ([#1558](https://github.com/hashicorp/terraform-provider-vault/pull/1558))
* fix: Make password_policy conflict with the formatter field: ([#1557](https://github.com/hashicorp/terraform-provider-vault/pull/1557))
* fix: Correct typo in `r/pki_secret_backend_root_cert` description: ([#1511](https://github.com/hashicorp/terraform-provider-vault/pull/1511))

## 3.8.0 (July 26, 2022)
FEATURES:
* Adds support for Kubernetes secrets engine:
  ([#1515](https://github.com/hashicorp/terraform-provider-vault/pull/1515))
* PKI: Add support for CPS URL in custom policy identifiers:
  ([#1495](https://github.com/hashicorp/terraform-provider-vault/pull/1495))

IMPROVEMENTS:
* Fix Import for OIDC Scope resource:
  ([#1548](https://github.com/hashicorp/terraform-provider-vault/pull/1548))
* Update entity alias creation to use entity lookup api:
  ([#1517](https://github.com/hashicorp/terraform-provider-vault/pull/1517))
  ([#1552](https://github.com/hashicorp/terraform-provider-vault/pull/1552))
* Add support for Consul secrets engine enhancements:
  ([#1518](https://github.com/hashicorp/terraform-provider-vault/pull/1518))
* auth/gcp: adds `custom_endpoint` parameter to backend config:
  ([#1482](https://github.com/hashicorp/terraform-provider-vault/pull/1482))
* auth/jwt: adds `user_claim_json_pointer` and `max_age` to roles:
  ([#1478](https://github.com/hashicorp/terraform-provider-vault/pull/1478))

BUGS:
* Support updating backend descriptions:
 ([#1550](https://github.com/hashicorp/terraform-provider-vault/pull/1550))
 ([#1543](https://github.com/hashicorp/terraform-provider-vault/pull/1543))
* Properly set the `base64_pem` in Vault for Couchbase:
 ([#1545](https://github.com/hashicorp/terraform-provider-vault/pull/1545))
* Fix bug where some rabbitmq config changes trigger erroneous mount recreation:
 ([#1542](https://github.com/hashicorp/terraform-provider-vault/pull/1542))
* Update `*kv_secrets*` resources to support namespaces:
 ([#1529](https://github.com/hashicorp/terraform-provider-vault/pull/1529))
* Do not validate JSON on OIDC scope template:
 ([#1547](https://github.com/hashicorp/terraform-provider-vault/pull/1547))

## 3.7.0 (June 15, 2022)
FEATURES:
* Support setting `namespace` by resource
 ([#1305](https://github.com/hashicorp/terraform-provider-vault/pull/1305))
 ([#1479](https://github.com/hashicorp/terraform-provider-vault/pull/1479))
* Add dedicated KV (v1/v2) secret engine resources, and data sources, supersedes `vault_generic_secret`
 ([#1457](https://github.com/hashicorp/terraform-provider-vault/pull/1457))

IMPROVEMENTS:
* Update vault libs to v1.10.3
 ([#1483](https://github.com/hashicorp/terraform-provider-vault/pull/1483))
* Drop debug log calls containing the full vault response
 ([#1477](https://github.com/hashicorp/terraform-provider-vault/pull/1477))
* `resource/token`: Add `metadata` support
 ([#1470](https://github.com/hashicorp/terraform-provider-vault/pull/1470))
* `resource/vault_ldap_auth_backend`: support LDAP `username_as_alias` attribute:
 ([#1460](https://github.com/hashicorp/terraform-provider-vault/pull/1460))
* `resource/vault_quota_rate_limit`: Add support for `interval` and `block_interval`:
 ([#1084](https://github.com/hashicorp/terraform-provider-vault/pull/1084))
* ci: Test against vault-enterprise 1.10.3-ent:
  ([#1461](https://github.com/hashicorp/terraform-provider-vault/pull/1461))

BUGS:
* `resource/auth_backend`: validate `path`, disallowing leading/trailing /
 ([#1471](https://github.com/hashicorp/terraform-provider-vault/pull/1471))
* `resource/vault_jwt_auth_backend_role`: fix `bound_claims` not being unset when empty
 ([#1469](https://github.com/hashicorp/terraform-provider-vault/pull/1469))
* `resource/cert_auth_backend`: add the correct field name: `allowed_organizational_units`
  ([#1496](https://github.com/hashicorp/terraform-provider-vault/pull/1496))

## 3.6.0 (May 18, 2022)
IMPROVEMENTS:
* `resource/pki_secret_backend_root_cert`: Force new root CA resource creation on out-of-band changes.
  ([#1428](https://github.com/hashicorp/terraform-provider-vault/pull/1428))
* `resource/pki_secret_backend_intermediate_set_signed`: Document complete usage example.
  ([#1452](https://github.com/hashicorp/terraform-provider-vault/pull/1452))
* `resource/pki_secret_backend_config_urls`: Add support for importing PKI config URLs
  ([#1451](https://github.com/hashicorp/terraform-provider-vault/pull/1451))
* `vault/resource_pki_secret_backend*`: Extend revocation support to other resources
  ([#1446](https://github.com/hashicorp/terraform-provider-vault/pull/1446))
* `vault/resource_pki_secret_backend*`: Force new root CA/cert resource creation on out-of-band changes.
  ([#1432](https://github.com/hashicorp/terraform-provider-vault/pull/1432))
* `datasource/generic_secret`: Improve documentation.
  ([#1390](https://github.com/hashicorp/terraform-provider-vault/pull/1390))
* `resource/ldap_auth_backend`: Support setting `userfilter`.
  ([#1378](https://github.com/hashicorp/terraform-provider-vault/pull/1378))
* `resource/aws_auth_backend_role`: Add `role_id` as a computed field.
  ([#1377](https://github.com/hashicorp/terraform-provider-vault/pull/1377))
* Auth: Handle CIDR prefix being stripped for hosts in `token_bound_cidrs`
  ([#1346](https://github.com/hashicorp/terraform-provider-vault/pull/1346))
* Add `allowed_serial_numbers` support
  ([#1119](https://github.com/hashicorp/terraform-provider-vault/pull/1119))
* `resource/pki_secret_backend_role`: Allow `key_type` to be set to `any`.
  ([#791](https://github.com/hashicorp/terraform-provider-vault/pull/791))
* `resource/aws_secret_backend_role`: Add `user_path` and `permissions_boundary_arn` arguments.
  ([#781](https://github.com/hashicorp/terraform-provider-vault/pull/781))

BUGS:
* `resource/pki_secret_backend_root_sign_intermediate`: Ensure that the `certificate_bundle`, and `ca_chain`
  do not contain duplicate certificates.
  ([#1428](https://github.com/hashicorp/terraform-provider-vault/pull/1428))
* `resource/identity_entity_alias`: Serialize create, update, and delete operations in order to prevent alias
  mismatches.
  ([#1429](https://github.com/hashicorp/terraform-provider-vault/pull/1429))
* `database_secret*`: Ignore mongodb-atlas `private_key` on read from Vault.
  mismatches.
  ([#1438](https://github.com/hashicorp/terraform-provider-vault/issues/1438))
* `resource/auth_backend`: Remove `ForceNew` behavior when updating `description`.
  ([#1439](https://github.com/hashicorp/terraform-provider-vault/pull/1439))
* `resource/identity_group_member_entity_ids`: Properly handle nil `member_entity_ids` in response.
  ([#1448](https://github.com/hashicorp/terraform-provider-vault/pull/1448))
* `resource/pki_secret_backend_role`: Fix TTL handling in PKI role.
  ([#1447](https://github.com/hashicorp/terraform-provider-vault/pull/1447))
* `resource/pki_secret_backend_role`: `key_usage` value should be computed.
  ([#1443](https://github.com/hashicorp/terraform-provider-vault/pull/1443))
* `resource/vault_pki_secret_backend_{cert,sign}`: Properly force a new resource whenever the cert is near expiry.
  ([#1440](https://github.com/hashicorp/terraform-provider-vault/pull/1440))
* `resource/identity_entity_alias`: Remove read operation on entity alias update.
  ([#1434](https://github.com/hashicorp/terraform-provider-vault/pull/1434))

## 3.5.0 (April 20, 2022)
FEATURES:
* Add MFA support: new resources `vault_mfa_okta`, `vault_mfa_totp`, `vault_mfa_pingid` ([#1395](https://github.com/hashicorp/terraform-provider-vault/pull/1395))
* *New* `resource/database_secrets_mount`: Configures any number of database secrets engines under
 a single, dedicated mount resource
 ([#1400](https://github.com/terraform-providers/terraform-provider-vault/pull/1400))

IMPROVEMENTS:
* `data/vault_generic_secret`: Add new field `with_lease_start_time` to `vault_generic_secret` datasource
  ([#1414](https://github.com/hashicorp/terraform-provider-vault/pull/1414))
* `resource/vault_ssh_secret_backend_role`: support configuring multiple public SSH key lengths in vault-1.10+
  ([#1413](https://github.com/terraform-providers/terraform-provider-vault/pull/1413))
* `resource/database_secret*`: Add support for configuring TLS, and the `username_template` field for the ElasticSearch.
* `resource/pki_secret_backend_cert`: Add support for optionally revoking the certificate upon resource destruction.
  ([#1411](https://github.com/terraform-providers/terraform-provider-vault/pull/1411))
* `provider`: Add support for setting the `tls_server_name` to use as the SNI host when connecting via TLS.
  ([#1145](https://github.com/terraform-providers/terraform-provider-vault/pull/1145)
* `docs`: Add links to Learn Tutorials.
  ([#1399](https://github.com/terraform-providers/terraform-provider-vault/pull/1399))

BUGS:
* `resource/identity_group`: Fix issue where the group's `member_entity_ids` were being unset in error on update.
  ([#1409](https://github.com/terraform-providers/terraform-provider-vault/pull/1409))
* `resource/transit_secret_backend_key`: Add `auto_rotate_period` field which deprecates `auto_rotate_interval`.
  ([#1402](https://github.com/hashicorp/terraform-provider-vault/pull/1402))

## 3.4.1 (March 31, 2022)
BUGS:
* `data/azure_access_credentials`: Fix panic when `tenant_id` and `subscription_id` are specified together; add new `environment` override field
  ([#1391](https://github.com/terraform-providers/terraform-provider-vault/pull/1391)).

IMPROVEMENTS:
* `resource/rabbitmq_secret_backend`: Add support for the `password_policy` and `username_template` fields
  ([#1276](https://github.com/terraform-providers/terraform-provider-vault/pull/1276))

## 3.4.0 (March 24, 2022)
FEATURES:
* `data/azure_access_credentials` Add `subscription_id` and `tenant_id` fields to used during credential validation ([#1384](https://github.com/terraform-providers/terraform-provider-vault/pull/1384))
* Add OIDC Provider support: new resources `vault_identity_oidc_scope`, `vault_identity_oidc_assignment`, `vault_identity_oidc_client`
 , `vault_identity_oidc_provider`, `vault_identity_oidc_public_keys`, `vault_identity_oidc_openid_config` ([#1363](https://github.com/hashicorp/terraform-provider-vault/pull/1363))

BUGS:
* `data/azure_access_credentials`: Fix credential validation ([#1381](https://github.com/terraform-providers/terraform-provider-vault/pull/1381)).

IMPROVEMENTS:
* `resource/database_secret_backend_connection`: Add `disable_escaping` parameter support to Redshift, HanaDB, Postgres and MSSQL ([#1321](https://github.com/hashicorp/terraform-provider-vault/pull/1321))
* `resource/transit_secret_backend_key`: Add `auto_rotate_interval` parameter support to Transit Key Backend ([#1345](https://github.com/hashicorp/terraform-provider-vault/pull/1345))
* `resource/consul_secret_backend_role`: Add support for Consul role ([#1366](https://github.com/hashicorp/terraform-provider-vault/pull/1366))
* `resource/consul_secret_backend_role`: Add support for Consul namespaces and partitions ([#1367](https://github.com/hashicorp/terraform-provider-vault/pull/1367))
* `resource/github_auth_backend`: Add support for `organization_id` field ([#1296](https://github.com/hashicorp/terraform-provider-vault/pull/1296))
* `resource/approle_auth_backend_role_secret_id`: Add `with_wrapped_accessor` to control how the resource ID is set ([#1166](https://github.com/hashicorp/terraform-provider-vault/pull/1166))

## 3.3.1 (February 25, 2022)
BUGS:
* `resource/identity_group`: Report an error upon duplicate resource creation failure. Document group name caveats. ([#1352](https://github.com/hashicorp/terraform-provider-vault/pull/1352))
* `resource/pki_secret_backend_root_sign_intermediate`: Fix panic when reading `ca_chain` from Vault ([#1357](https://github.com/hashicorp/terraform-provider-vault/issues/1357))
* `resource/raft_snapshot_agent_config`: Properly handle nil response on read ([#1360](https://github.com/hashicorp/terraform-provider-vault/pull/1360))
* `resource/identity_*`: Ensure non-existent entities are handled properly ([#1361](https://github.com/hashicorp/terraform-provider-vault/pull/1361))
* `resource/dentity_group_member_entity_ids`: Properly handle nil `member_identity_ids` on read ([#1356](https://github.com/hashicorp/terraform-provider-vault/pull/1356))

## 3.3.0 (February 17, 2022)
FEATURES:
* Add KMIP support: new resources `vault_kmip_secret_backend`, `vault_kmip_secret_scope` and `vault_kmip_secret_role` ([#1339](https://github.com/hashicorp/terraform-provider-vault/pull/1339))

BUGS:
* `resource/kubernetes_auth_backend_config`: Ensure `disable_iss_validation` is honored in all cases ([#1315](https://github.com/hashicorp/terraform-provider-vault/pull/1315))
* `resource/database_secret_backend_connection`: Add error handling for unrecognized plugins on read ([#1325](https://github.com/hashicorp/terraform-provider-vault/pull/1325))
* `resource/kubernetes_auth_backend_config`: Prevent persistent diff for `kubernetes_ca_cert` when it is loaded by the backend ([#1337](https://github.com/hashicorp/terraform-provider-vault/pull/1337))

IMPROVEMENTS:
* `resource/token_auth_backend_role`: Add `allowed_policies_glob` and `disallowed_polices_glob` ([#1316](https://github.com/hashicorp/terraform-provider-vault/pull/1316))
* `resource/database_secret_backend_connection`: Add support for configuring the secret engine's `plugin_name` ([#1320](https://github.com/hashicorp/terraform-provider-vault/pull/1320))
* `resource/pki_secret_backend_root_sign_intermediate`: Update schema for `ca_chain` from string to a list of
  `issuing_ca` and `certificate`, add new `certificate_bundle` attribute that provides the concatenation of the
  intermediate and issuing CA certificates (PEM encoded) ([#1330](https://github.com/hashicorp/terraform-provider-vault/pull/1330))
* `resource/azure_secret_backend`: Add support for setting `use_microsoft_graph_api` ([#1335](https://github.com/hashicorp/terraform-provider-vault/pull/1335))
* `r/d/kubernetes_auth_backend_role`: Add support for setting and getting `alias_name_source` ([#1336](https://github.com/hashicorp/terraform-provider-vault/pull/1336))
* `resource/database_secret_backend_connection`: Add `username` and `password` fields to all DB Engines that support them ([#1331](https://github.com/hashicorp/terraform-provider-vault/pull/1331))
* `resource/token_auth_backend_role`: Add support for setting `allowed_entity_aliases` ([#1126](https://github.com/hashicorp/terraform-provider-vault/pull/1126))
* `resource/ad_secret_backend`:  Restore deprecated `formatter`, and `length` fields. ([#1341](https://github.com/hashicorp/terraform-provider-vault/pull/1341))
* `resource/ldap_auth_backend`: Add support for setting `case_sensitive_names` ([#1176](https://github.com/hashicorp/terraform-provider-vault/pull/1176))

## 3.2.1 (January 20, 2022)
BUGS:
* `resource/rabbitmq_secret_backend_role`: Add nil check when reading RabbitMQ role from Vault ([#1312](https://github.com/hashicorp/terraform-provider-vault/pull/1312))

## 3.2.0 (January 19, 2022)
BUGS:
* `resource/aws_secret_backend_role`: Ensure all updated fields are applied ([#1277](https://github.com/hashicorp/terraform-provider-vault/pull/1277))

IMPROVEMENTS:
* `resource/database_secret_backend_connection`: Add support for configuring Redshift databases ([#1279](https://github.com/hashicorp/terraform-provider-vault/pull/1279))
* `resource/pki_secret_backend_intermediate_cert_request`: Add support for the `ed25519` key_type ([#1278](https://github.com/hashicorp/terraform-provider-vault/pull/1278))
* `resource/rabbitmq_secret_backend_role`: Add support for `vhost_topics` ([#1246](https://github.com/hashicorp/terraform-provider-vault/pull/1246))
* `resource/vault_mount`: Add support for `audit_non_hmac_request_keys` and `audit_non_hmac_response_keys` ([#1297](https://github.com/hashicorp/terraform-provider-vault/pull/1297))
* `resource/vault_aws_secret_backend`: Add support for `username_template` ([#1292](https://github.com/hashicorp/terraform-provider-vault/pull/1292))

## 3.1.1 (December 22, 2021)
BUGS:
* Prevent new `entity` read failures when the `VAULT_TOKEN` environment variable is not set ([#1270](https://github.com/hashicorp/terraform-provider-vault/pull/1270))

## 3.1.0 (December 22, 2021)
FEATURES:
* `provider`: Add support retrying entity reads for `Client Controlled Consistency` type operations ([#1263](https://github.com/hashicorp/terraform-provider-vault/pull/1263))
* `provider`: Add support for optionally creating a batch child token via the `skip_child_token` option ([#775](https://github.com/hashicorp/terraform-provider-vault/pull/775))

IMPROVEMENTS:
* `data/policy_document`: Add support for `patch` capability for vault-1.9+. ([#1238](https://github.com/hashicorp/terraform-provider-vault/pull/1238))
* `resource/database_secret_backend_connection`: Add support for InfluxDB connections ([#1121](https://github.com/hashicorp/terraform-provider-vault/pull/1121))
* `resource/generic_secret`: Add support for deleting all version data for a KV-V2 secret ([#1254](https://github.com/hashicorp/terraform-provider-vault/pull/1254))
* `resource/database_secret_backend_connection`: Add support configuring `Contained Databases` for `mssql` ([#1259](https://github.com/hashicorp/terraform-provider-vault/pull/1259))
* `resource/vault_jwt_auth_backend`: Add `oidc_response_mode`, `oidc_response_types`, and `namespace_in_state` fields ([#1244](https://github.com/hashicorp/terraform-provider-vault/pull/1244))
* Add better error reporting whenever invalid JSON `metadata` is encountered ([#1262](https://github.com/hashicorp/terraform-provider-vault/pull/1262))
* `resource/vault_identity_entity_alias`: Add `custom_metadata` support for entity aliases ([#1235](https://github.com/hashicorp/terraform-provider-vault/pull/1235))
* `resource/approle_auth_backend_role_secret_id`: Update Vault provider to be compatible with Vault 1.9 changes ([#1242](https://github.com/hashicorp/terraform-provider-vault/pull/1242))
* `provider`: Encrypt logged HTTP secret header values ([#1250](https://github.com/hashicorp/terraform-provider-vault/pull/1250))
* `provider`: Optionally log request and response bodies ([#1251](https://github.com/hashicorp/terraform-provider-vault/pull/1251))

BUGS:
* `resource/identity_group_policies`: Fix potential `nil` panic in type conversion for API policies ([#1245](https://github.com/hashicorp/terraform-provider-vault/pull/1245))
* `resource/aws_secret_backend_role`: Fix for properly detecting changes in the JSON policy document ([#1014](https://github.com/hashicorp/terraform-provider-vault/pull/1014))

## 3.0.1 (November 23, 2021)

BUGS:
* `resource/aws_secret_backend_role`: Prevent invalid `policy_arns` from being created ([#1229](https://github.com/hashicorp/terraform-provider-vault/pull/1229))
* `resource/approle_auth_backend_secret_id`: Handle `nil` `cidr_list` introduced in [vault-1.9.0](https://github.com/hashicorp/vault/issues/13226) ([#1230](https://github.com/hashicorp/terraform-provider-vault/pull/1230))
* `resource/kubernetes_auth_backend_config`: Ensure `disable_iss_validation` is properly set in vault-1.9+ ([#1231](https://github.com/hashicorp/terraform-provider-vault/pull/1231))

## 3.0.0 (November 17, 2021)

FEATURES:
* **New Resource** `vault_raft_autopilot`: Configure Vault's [Raft Autopilot settings](https://www.vaultproject.io/api-docs/system/storage/raftautopilot) ([#1210](https://github.com/hashicorp/terraform-provider-vault/pull/1210))

IMPROVEMENTS:
* Upgrade Terraform Plugin SDK to v2
* Add support for client controlled consistency on Vault Enterprise ([#1188](https://github.com/hashicorp/terraform-provider-vault/pull/1188))
* `resource/jwt_auth_backend_role`: Add field `disable_bound_claims_parsing` to disable bound claim value parsing, which is useful when values contain commas ([#1200](https://github.com/hashicorp/terraform-provider-vault/pull/1200))
* `resource/transform_template`: Add `encode_format` and `decode_formats` fields for `Vault Enterprise` with the `Advanced Data Protection Transform Module` ([#1214](https://github.com/hashicorp/terraform-provider-vault/pull/1214))
* `data/generic_secret`: Store `lease_start_time` UTC. ([#1216](https://github.com/hashicorp/terraform-provider-vault/pull/1216))
* `resource/identity_entity_alias`: Add support for configuring `custom_metadata`. ([#1235](https://github.com/hashicorp/terraform-provider-vault/pull/1235))

BUGS:
* `data/gcp_auth_backend_role`: Report an error when attempting to access a nonexistent role. ([#1184](https://github.com/hashicorp/terraform-provider-vault/pull/1184))
* `data/generic_secret`: Ensure `lease_start_time` is stored in RFC3339 format. ([#770](https://github.com/hashicorp/terraform-provider-vault/pull/770))

## 2.24.1 (October 05, 2021)

BUGS:
* `resource/vault_raft_snapshot_agent_config`: Fix bug where cloud provider was missing and google_endpoint is returned as false instead of null ([#1173](https://github.com/hashicorp/terraform-provider-vault/pull/1173))

## 2.24.0 (September 15, 2021)

FEATURES:
* **New Database Resource**: Added support for the `snowflake-database-plugin` to `vault_database_secret_backend_connection` ([#983](https://github.com/hashicorp/terraform-provider-vault/pull/983))
* `resource/vault_raft_snapshot_agent_config`: Provision [Raft Snapshot Agent Configurations](https://www.vaultproject.io/api-docs/system/storage/raftautosnapshots) in Vault Enterprise. ([#1139](https://github.com/hashicorp/terraform-provider-vault/pull/1139))

IMPROVEMENTS:
* `resource/database_secret_backend_connection`: Add username_template to vault_database_secret_backend_connection ([#1103](https://github.com/hashicorp/terraform-provider-vault/pull/1103))
* `resource/ldap_auth_backend`: Allow the creation of `local` mounts ([#1115](https://github.com/hashicorp/terraform-provider-vault/pull/1115))
* `resource/jwt_auth_backend`: Allow the creation of `local` mounts ([#1115](https://github.com/hashicorp/terraform-provider-vault/pull/1115))
* `resource/consul_secret_backend`: Allow the creation of `local` mounts ([#1115](https://github.com/hashicorp/terraform-provider-vault/pull/1115))

BUGS:
* `resource/vault_identity_group`: Fix bug where member_entity_ids & member_group_ids were attempted to be managed on external identity groups ([#1134](https://github.com/hashicorp/terraform-provider-vault/pull/1134))

## 2.23.0 (August 18, 2021)

FEATURES:
* **New Resource** `vault_gcp_secret_static_account`: Provision Static Accounts in the [GCP Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html) ([#1094](https://github.com/hashicorp/terraform-provider-vault/pull/1094))

IMPROVEMENTS:
* `resource/database_secret_backend/mysql`: Add tls_certificate_key and tls_ca options ([#1098](https://github.com/hashicorp/terraform-provider-vault/pull/1098))

BUGS:
* `resource/jwt_auth_backend`: Fixed bug where `provider_config` did not configure non-string values correctly ([#1118](https://github.com/hashicorp/terraform-provider-vault/pull/1118))
* `resource/gcp_auth_backend`: Support importing resource ([#1125](https://github.com/hashicorp/terraform-provider-vault/pull/1125))
* `resource/okta_auth_backend`: Support importing resource ([#1123](https://github.com/hashicorp/terraform-provider-vault/pull/1123))
* `resource/audit`: List audit only once during read ([#1138](https://github.com/hashicorp/terraform-provider-vault/pull/1138))
* `resource/identity_oidc_key`: Error handling for identity oidc key vault calls ([#1142](https://github.com/hashicorp/terraform-provider-vault/pull/1142))

## 2.22.1 (July 23, 2021)

BUGS:
* `resource/vault_identity_group`: Correctly handle the case of a preexisting identity group, suggest resource import in this case ([#1014](https://github.com/hashicorp/terraform-provider-vault/pull/1010))
* `resource/jwt_auth_backend`: Reverted ([#960](https://github.com/hashicorp/terraform-provider-vault/pull/960)) due to migration errors ([#1114](https://github.com/hashicorp/terraform-provider-vault/pull/1114))

## 2.22.0 (July 22, 2021)

FEATURES:
* **New Resource** `vault_quota_lease_count`: Adds ability to manage lease-count quota's (Vault Enterprise Feature) ([#948](https://github.com/hashicorp/terraform-provider-vault/pull/948))

IMPROVEMENTS:
* Remove last dependency on `github.com/terraform-providers` ([#1090](https://github.com/hashicorp/terraform-provider-vault/pull/1090))

BUGS:
* `resource/vault_identity_group`: Fix bug where metadata values are not removed if removed from file ([#1061](https://github.com/hashicorp/terraform-provider-vault/pull/1061))
* `resource/jwt_auth_backend`: Fixed bug where `provider_config` only supported string values ([#960](https://github.com/hashicorp/terraform-provider-vault/pull/960))
* `provider`: Fix inconsistent handling of `namespace` when `wrapping_ttl` was specified in any resource ([#1107](https://github.com/hashicorp/terraform-provider-vault/pull/1107))

## 2.21.0 (June 17, 2021)

FEATURES:
* `data/vault_gcp_auth_backend_role`: Added GCP auth role data source to fetch role ID ([#1011](https://github.com/hashicorp/terraform-provider-vault/pull/1011))

IMPROVEMENTS:
 * `provider/auth_login`: Supprt AWS STS signing when `method=aws` for in `auth_type` ([#1060](https://github.com/hashicorp/terraform-provider-vault/pull/1060))
 * `resource/vault_ldap_auth_backend`: Add `client_tls_cert` and `client_tls_key` options ([#1074](https://github.com/hashicorp/terraform-provider-vault/pull/1074))
 * `resource/vault_identity_entity`Added additional logging information about entity ([#987](https://github.com/hashicorp/terraform-provider-vault/pull/987))

## 2.20.0 (May 19, 2021)

IMPROVEMENTS:
* `resource/vault_azure_secret_backend`: Added support for updating the backend ([#1009](https://github.com/hashicorp/terraform-provider-vault/pull/1009))
* `resource/vault_aws_secret_backend`: Add `iam_endpoint` and `sts_endpoint` options ([#1043](https://github.com/hashicorp/terraform-provider-vault/pull/1043))

BUG FIXES:
* `resource/vault_gcp_auth_backend`: Support nested backend paths ([#1050](https://github.com/hashicorp/terraform-provider-vault/pull/1050))
* `resource/vault_kubernetes_auth_backend_role`: allow unset audience ([#1022](https://github.com/hashicorp/terraform-provider-vault/pull/1022))
* `resource/vault_identity_entity`: Fix bug where values are not removed if removed from file ([#1054](https://github.com/hashicorp/terraform-provider-vault/pull/1054))

## 2.19.1 (April 21, 2021)

SECURITY:
* `resource/vault_gcp_auth_backend_role`: Fixed typo in `bound_labels` parameter name causing no values to be applied to created roles [CVE-2021-30476](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30476) ([#1028](https://github.com/hashicorp/terraform-provider-vault/pull/1028))

## 2.19.0 (March 17, 2021)

FEATURES:
* **New Resource**: `terraform_cloud_secret` resources ([#959](https://github.com/hashicorp/terraform-provider-vault/pull/959))

IMPROVEMENTS:
* `resource/pki_secret_backend`: Support allowed_domains_template option for vault_pki_secret_backend_role ([#869](https://github.com/hashicorp/terraform-provider-vault/pull/869))

BUG FIXES:
* `resource/vault_identity_group`: Don't send `name` parameter unless specified ([#1002](https://github.com/hashicorp/terraform-provider-vault/pull/1002))

## 2.18.0 (January 21, 2021)

FEATURES:
* **New Resource**: `vault_password_policy` resource ([#927](https://github.com/hashicorp/terraform-provider-vault/pull/927))

IMPROVEMENTS:
* `resource/vault_consul_secret_backend`: Extend consul secret engine definition to cover all vault parameters ([#910](https://github.com/hashicorp/terraform-provider-vault/pull/910))
* `resource/vault_jwt_auth_backend`: Added support for `provider_config` ([#943](https://github.com/hashicorp/terraform-provider-vault/pull/943))

## 2.17.0 (December 15, 2020)

FEATURES:
* **New Data Source**: `vault_nomad_access_token` data source ([#923](https://github.com/hashicorp/terraform-provider-vault/pull/923))
* **New Resource**: `vault_nomad_secret_backend` resource ([#923](https://github.com/hashicorp/terraform-provider-vault/pull/923))
* **New Resource**: `vault_nomad_secret_role` resource ([#923](https://github.com/hashicorp/terraform-provider-vault/pull/923))

IMPROVEMENTS:
* `resource/vault_audit`: added support for local mount to prevent replicating the audit backend ([#915](https://github.com/terraform-providers/terraform-provider-vault/pull/915))
* `resource/jwt_auth_backend_role`: Added support for using globs in matching bound_claims ([#877](https://github.com/hashicorp/terraform-provider-vault/pull/877))
* `resource/vault_aws_auth_backend_client`: Added `sts_region` parameter ([#931](https://github.com/hashicorp/terraform-provider-vault/pull/931))
* `resource/vault_azure_secret_backend_role`: Added support for `azure_groups` ([#891](https://github.com/hashicorp/terraform-provider-vault/pull/891))
* `resource/vault_identity_oidc_role`: `client_id` parameter can optionally be configured ([#815](https://github.com/terraform-providers/terraform-provider-vault/pull/815))

BUG FIXES:

* `resource/vault_identity_entity`: Fixed nil pointer exception ([#899](https://github.com/terraform-providers/terraform-provider-vault/pull/899))
* `resource/vault_mount`: Fixed bug where mount was deleted when description was changed ([#929](https://github.com/hashicorp/terraform-provider-vault/pull/929))

## 2.16.0 (November 19, 2020)

FEATURES:
* **New Data Source**: `vault_ad_access_credentials` data source ([#902](https://github.com/terraform-providers/terraform-provider-vault/pull/902))
* **New Resource**: `vault_ad_secret_backend` resource ([#902](https://github.com/terraform-providers/terraform-provider-vault/pull/902))
* **New Resource**: `vault_ad_secret_role` resource ([#902](https://github.com/terraform-providers/terraform-provider-vault/pull/902))
* **New Resource**: `vault_ad_secret_library` resource ([#902](https://github.com/terraform-providers/terraform-provider-vault/pull/902))

IMPROVEMENTS:

* `resource/vault_gcp_auth_backend`: added support for local mount to prevent replicating the secret engine ([#861](https://github.com/terraform-providers/terraform-provider-vault/pull/861))
* `data.vault_aws_access_credentials`: Add optional ttl parameter to data source ([#878](https://github.com/terraform-providers/terraform-provider-vault/pull/878))

BUG FIXES:

* `resource/vault_jwt_auth_backend`: Fix possible reoccuring diff when using `oidc_client_secret` ([#803](https://github.com/terraform-providers/terraform-provider-vault/pull/803))

## 2.15.0 (October 21, 2020)

FEATURES:

* **New Data Source**: `vault_transit_decrypt` data source ([#872](https://github.com/terraform-providers/terraform-provider-vault/pull/872)).
* **New Data Source**: `vault_transit_encrypt` data source ([#872](https://github.com/terraform-providers/terraform-provider-vault/pull/872)).

IMPROVEMENTS:

* `resource/vault_gcp_secret_backend`: added support for `local` mount to prevent replicating the secret engine ([#855](https://github.com/terraform-providers/terraform-provider-vault/pull/855))
* `resource/vault_ssh_secret_backend_role`: added support for new `allowed_users_template` argument([#875](https://github.com/terraform-providers/terraform-provider-vault/pull/875))
* `resource/vault_ssh_secret_backend_role`: added support for new `algorithm_signer` argument([#809](https://github.com/terraform-providers/terraform-provider-vault/pull/809))
* `resource/vault_kubernetes_auth_backend_config`: Add `disable_iss_validation` and `disable_local_ca_jwt` config parameters to k8s auth backend ([#870](https://github.com/terraform-providers/terraform-provider-vault/pull/870))
* `data/vault_kubernetes_auth_backend_config`: Add `disable_iss_validation` and `disable_local_ca_jwt` config parameters to k8s auth backend ([#870](https://github.com/terraform-providers/terraform-provider-vault/pull/870))

## 2.14.0 (September 15, 2020)
FEATURES:

* **New Resource:** `vault_quota_rate_limit` resource to manage resource quota limit ([#825](https://github.com/terraform-providers/terraform-provider-vault/pull/825)).

BUG FIXES:


* `resource/vault_aws_secret_backend_role`: fix AWS Secrets Engine Role resource to allow only IAM Groups ([#862](https://github.com/terraform-providers/terraform-provider-vault/pull/862))
* `resource/vault_ssh_secret_backend_ca`: detect misconfigured resource and remove from state ([#856](https://github.com/terraform-providers/terraform-provider-vault/pull/856))

## 2.13.0 (August 27, 2020)

IMPROVEMENTS:

* `resource/transit_secret_backend_key`: add supported by Vault type of algorithm rsa-3072 ([#773](https://github.com/terraform-providers/terraform-provider-vault/pull/773))
* `data.vault_generic_secret`: Mark `data` and `data_json` as `Sensitive` ([#844](https://github.com/terraform-providers/terraform-provider-vault/pull/844))
* Add `iam_groups` to `vault_aws_secret_backend_role` ([#826](https://github.com/terraform-providers/terraform-provider-vault/pull/826))
* Add support for `uri_sans` parameter for resource `vault_pki_secret_backend_cert` ([#759](https://github.com/terraform-providers/terraform-provider-vault/pull/759))

BUG FIXES:

* `data/vault_generic_secret`: Fix perpetual diff when using Terraform v0.13.0  ([#849](https://github.com/terraform-providers/terraform-provider-vault/pull/849))
* `data.vault_aws_access_credentials`: Re-add support for passing region information stored in Vault backend to AWS Config ([#841](https://github.com/terraform-providers/terraform-provider-vault/pull/841))

## 2.12.2 (July 31, 2020)

BUG FIXES:

* `data.vault_aws_access_credentials`: Revert [#832](https://github.com/terraform-providers/terraform-provider-vault/pull/832), which inadvertently introduced issues when the token policy did not have the required permissions to read the root configuration. ([#837](https://github.com/terraform-providers/terraform-provider-vault/pull/837))

## 2.12.1 (July 30, 2020)

BUG FIXES:

* `data.vault_aws_access_credentials`: Add support for passing region information stored in Vault backend to AWS Config ([#832](https://github.com/terraform-providers/terraform-provider-vault/pull/832))

## 2.12.0 (July 20, 2020)
FEATURES:

* **New Resource:** `vault_identity_group_member_entity_ids` ([#724](https://github.com/terraform-providers/terraform-provider-vault/pull/724)).
* **New Resource:** `vault_transform_alphabet` ([#783](https://github.com/terraform-providers/terraform-provider-vault/pull/783)).
* **New Resource:** `vault_transform_role` ([#783](https://github.com/terraform-providers/terraform-provider-vault/pull/783)).
* **New Resource:** `vault_transform_template` ([#783](https://github.com/terraform-providers/terraform-provider-vault/pull/783)).
* **New Resource:** `vault_transform_transformation` ([#783](https://github.com/terraform-providers/terraform-provider-vault/pull/783)).
* **New Data Source**: `vault_transform_encode` data source ([#783](https://github.com/terraform-providers/terraform-provider-vault/pull/783)).
* **New Data Source**: `vault_transform_decode` data source ([#783](https://github.com/terraform-providers/terraform-provider-vault/pull/783)).

IMPROVEMENTS:

* resource/vault_mount: Adds support for the `external_entropy_access` field ([#792](https://github.com/terraform-providers/terraform-provider-vault/pull/792)).
* resource/vault_jwt_auth_backend: enable existing JWT Auth backends to be imported ([#806](https://github.com/terraform-providers/terraform-provider-vault/pull/806)).
* resource/vault_jwt_auth_backend: store `type` and `tune` information in state ([#806](https://github.com/terraform-providers/terraform-provider-vault/pull/806)).

## 2.11.0 (May 21, 2020)

IMPROVEMENTS:

* Add `headers` provider configuration setting to allow setting HTTP headers for all requests to the Vault server ([#730](https://github.com/terraform-providers/terraform-provider-vault/pull/730)).

BUG FIXES:

* `vault_jwt_auth_backend`: Fix plan error when `oidc_discovery_url`, `jwks_url`, or `jwt_validation_pubkeys` is set to a value that is not known until apply time ([#753](https://github.com/terraform-providers/terraform-provider-vault/pull/753)).
* `vault_pki_secret_backend_root_cert`, `vault_pki_secret_backend_root_sign_intermediate`, and `vault_pki_secret_backend_sign`: Fix `serial` field ([#761](https://github.com/terraform-providers/terraform-provider-vault/pull/761)).
* `vault_token`: Avoid panic when `vault_token` is gone from the server ([#740](https://github.com/terraform-providers/terraform-provider-vault/pull/740)).
* `vault_approle_auth_backend_role`: Fix perpetual diff when `policies` and `period` are updated to be `token_policies` and `token_period` ([#744](https://github.com/terraform-providers/terraform-provider-vault/pull/744)).
* `vault_jwt_auth_backend_role`: Fix crash when `bound_audiences` is empty ([#763](https://github.com/terraform-providers/terraform-provider-vault/pull/763)).
* `vault_identity_group`: Fix removal of `policies`, `member_group_ids`, and `member_entity_ids` ([#766](https://github.com/terraform-providers/terraform-provider-vault/pull/766)).

## 2.10.0 (April 03, 2020)

FEATURES:

* Add `vault_azure_access_credentials` data source that retries creds before returning them ([#713](https://github.com/terraform-providers/terraform-provider-vault/pull/713)).
* To `vault_database_secret_backend_connection`, add support for the `elasticsearch-database-plugin` ([#704](https://github.com/terraform-providers/terraform-provider-vault/pull/704)).

IMPROVEMENTS:

* Add `add_address_to_env` argument to set the value of the provider's address argument as the VAULT_ADDR environment variable in the Terraform process, enabling VAULT_ADDR external token helpers to work with this provider ([#651](https://github.com/terraform-providers/terraform-provider-vault/pull/651)).
* Provide the ability to encrypt generated tokens using Keybase when using `/auth/token/create`, `/auth/token/create-orphan`, or `/auth/token/create/{role_name}` ([#686](https://github.com/terraform-providers/terraform-provider-vault/pull/686)).

BUG FIXES:

* In `vault_aws_auth_backend_role`, allow `role_arns` and `policy_arns` to be used together ([#710](https://github.com/terraform-providers/terraform-provider-vault/pull/710)).

## 2.9.0 (March 13, 2020)

FEATURES:

* Add `vault_alicloud_auth_backend_role` resource ([#673](https://github.com/terraform-providers/terraform-provider-vault/pull/673)).

IMPROVEMENTS:

* Allow `/` character in the group_name field of the `okta_auth_backend_group` resource ([#687](https://github.com/terraform-providers/terraform-provider-vault/pull/687)).
* Support `not_before_duration` property in `pki_secret_backend_role` ([#698](https://github.com/terraform-providers/terraform-provider-vault/pull/698)).

BUG FIXES:

* Fix `vault_cert_auth_backend_role` deletion ([#690](https://github.com/terraform-providers/terraform-provider-vault/pull/690)).
* Fix `use_token_groups` changes not being applied properly in `vault_ldap_auth_backend` resource ([#674](https://github.com/terraform-providers/terraform-provider-vault/pull/674)).

## 2.8.0 (February 05, 2020)

IMPROVEMENTS:

* Adds ability to choose a specific AWS ARN in vault_aws_access_credentials when a Vault role has multiple ARNs configured ([#661](https://github.com/terraform-providers/terraform-provider-vault/pull/661)).
* Updates to Go 1.13 ([#642](https://github.com/terraform-providers/terraform-provider-vault/pull/642)).
* Adds doc on multiple namespace support ([#654](https://github.com/terraform-providers/terraform-provider-vault/pull/654)).
* Sorts `vault_policy_document` data source allowed/denied parameters by key name ([#656](https://github.com/terraform-providers/terraform-provider-vault/pull/656)).
* Adds support to `vault_auth_backend` for common backend tune parameters. Also allows updating Max TTL, Default TTL and Visibility Listing tuning settings on `vault_auth_backend` without forcing a new resource ([#650](https://github.com/terraform-providers/terraform-provider-vault/pull/650)).

BUG FIXES:

* Fix panic when reading unconfigured PKI mount URLs ([#641](https://github.com/terraform-providers/terraform-provider-vault/pull/641)).
* Update JWT bound_audiences to be optional ([649](https://github.com/terraform-providers/terraform-provider-vault/pull/649)).
* Solves permanent diff with the Mongo database connection URL ([#659](https://github.com/terraform-providers/terraform-provider-vault/pull/659) and [#662](https://github.com/terraform-providers/terraform-provider-vault/pull/662)).
* Fixes an issue where the "vault_ldap_auth_backend_user" resource did not respect an empty `groups` value ([#655](https://github.com/terraform-providers/terraform-provider-vault/pull/655)).

## 2.7.1 (January 03, 2020)

BUG FIXES:

* For the `/gcp/config` endpoint, fixes issue where credentials weren't being updated when changed ([#635](https://github.com/terraform-providers/terraform-provider-vault/pull/635)).
* For the `/aws/config/root` endpoint, no longer requires `access_key` or `secret_key` ([#634](https://github.com/terraform-providers/terraform-provider-vault/pull/634)).

## 2.7.0 (December 06, 2019)

FEATURES:

* For the `/sys/auth` endpoint, adds a new data source ([#606](https://github.com/terraform-providers/terraform-provider-vault/pull/606)).

IMPROVEMENTS:

* For the Vault child token created for Terraform to use during a run, adds a `token_name` field for easier identification in Vault ([#594](https://github.com/terraform-providers/terraform-provider-vault/pull/594)).
* For the `/ssh/roles/{role}` endpoint, adds support for `allowed_user_key_lengths` ([#605](https://github.com/terraform-providers/terraform-provider-vault/pull/605)).
* For the `/sys/mounts/{path}` endpoint, adds support for `seal_wrap` ([#616](https://github.com/terraform-providers/terraform-provider-vault/pull/616)).
* For the `/auth/kubernetes/config` endpoints, adds support for `issuer` ([#601](https://github.com/terraform-providers/terraform-provider-vault/pull/601)).
* For the `/auth/kubernetes/role/{name}` endpoints, adds support for `audience` ([#601](https://github.com/terraform-providers/terraform-provider-vault/pull/601)).

BUG FIXES:

* For the `/identity/entity-alias` endpoint, fixes updates to the `name` field ([#610](https://github.com/terraform-providers/terraform-provider-vault/pull/610)).

## 2.6.0 (November 08, 2019)

FEATURES:

* Adds a resource for the `/database/static-roles/{name}` endpoint ([#577](https://github.com/terraform-providers/terraform-provider-vault/pull/577)).
* Adds a resource for the `/identity/lookup/entity` endpoint ([#587](https://github.com/terraform-providers/terraform-provider-vault/pull/587)).

IMPROVEMENTS:

* Improved deprecation notices for Vault 1.2 token.* fields ([#565](https://github.com/terraform-providers/terraform-provider-vault/pull/565)).
* Adds new JWT Auth role fields introduced with Vault 1.2 ([#566](https://github.com/terraform-providers/terraform-provider-vault/pull/566)).
* Eliminates the need to add an outer delay while waiting for AWS creds to propagate ([#571](https://github.com/terraform-providers/terraform-provider-vault/pull/571)).
* For the `/consul/roles/{name}` endpoint, adds support for `ttl`, `max_ttl`, `token_type`, and `local` fields ([#581](https://github.com/terraform-providers/terraform-provider-vault/pull/581)).
* For the `/sys/namespaces/{path}` endpoint, uses the `path` for the namespace ID to allow imports ([#570](https://github.com/terraform-providers/terraform-provider-vault/pull/570)).

BUG FIXES:

* Fix panic when trying to write an entity alias that already exists ([#573](https://github.com/terraform-providers/terraform-provider-vault/pull/573)).

## 2.5.0 (October 17, 2019)

IMPROVEMENTS:

* Migrates to using the standalone Terraform plugin SDK ([#558](https://github.com/terraform-providers/terraform-provider-vault/pull/558)).

## 2.4.0 (October 11, 2019)

FEATURES:

* Adds support for alternative auth methods using a method-agnostic implementation ([#552](https://github.com/terraform-providers/terraform-provider-vault/pull/552)).
* Adds a resource for the "/consul/roles/{name}" endpoint ([#480](https://github.com/terraform-providers/terraform-provider-vault/pull/480)).
* Adds a resource for the "/pki/config/crl" endpoint ([#506](https://github.com/terraform-providers/terraform-provider-vault/pull/506)).

IMPROVEMENTS:

* Adds support for Vault 1.2+ token fields to LDAP auth ([#553](https://github.com/terraform-providers/terraform-provider-vault/pull/553))
* Adds support for configuring the Transit cache ([#548](https://github.com/terraform-providers/terraform-provider-vault/pull/548))
* Adds support for updates to the identity group alias field ([#536](https://github.com/terraform-providers/terraform-provider-vault/pull/536)).
* Adds support for reading the AWS access key and region from the AWS client config ([#539](https://github.com/terraform-providers/terraform-provider-vault/pull/539)).
* In AWS auth, only updates the access key and secret if they've changed ([#540](https://github.com/terraform-providers/terraform-provider-vault/pull/540)).
* Adds support for `"root_rotation_statements"` in the database secret engine's connection params ([#530](https://github.com/terraform-providers/terraform-provider-vault/pull/530)).
* Adds support for `token_type` and `allowed_response_headers` in Github and JWT auth backends ([#556](https://github.com/terraform-providers/terraform-provider-vault/pull/556))

BUG FIXES:

* Fixes incorrect handling of user and team policies in the Github auth backend ([#543](https://github.com/terraform-providers/terraform-provider-vault/pull/543)).

## 2.3.0 (September 06, 2019)

IMPROVEMENTS:

* Adds support for importing roles in "vault_gcp_auth_backend_role" ([#517](https://github.com/terraform-providers/terraform-provider-vault/pull/517)).
* Adds support for importing groups in "vault_okta_auth_backend_group" ([#514](https://github.com/terraform-providers/terraform-provider-vault/pull/514)).
* Adds JWKS configuration options to "vault_jwt_auth_backend" ([#483](https://github.com/terraform-providers/terraform-provider-vault/pull/483)).
* Adds support for response wrapping to "vault_approle_auth_backend_role_secret_id" ([#518](https://github.com/terraform-providers/terraform-provider-vault/pull/518)).

BUG FIXES:

* Fixes an issue where using mount type "kv-v2" in "vault_mount" would continuously recreate the resource ([#515](https://github.com/terraform-providers/terraform-provider-vault/pull/515)).
* Fixes an issue where the "vault_token" resource would try to renew the access token instead of the resource token ([#423](https://github.com/terraform-providers/terraform-provider-vault/pull/423)).
* In the "vault_gcp_auth_backend", marks "credentials" as optional rather than required ([#509](https://github.com/terraform-providers/terraform-provider-vault/pull/509)).
* Fixes an issue where "vault_pki_secret_backend_config_urls" was forming an invalid URL for updating ([#512](https://github.com/terraform-providers/terraform-provider-vault/pull/512)).


## 2.2.0 (August 09, 2019)

FEATURES:

* Adds a datasource for the "/identity/lookup/entity" and "/identity/lookup/group" endpoints ([#494](https://github.com/terraform-providers/terraform-provider-vault/pull/494)).
* Adds a resource for the "/azure/roles/{name}" endpoint ([#493](https://github.com/terraform-providers/terraform-provider-vault/pull/493)).
* Adds a resource for the "/identity/oidc/config", "/identity/oidc/key/{name}", "/identity/oidc/key/{key_name}", and "/identity/oidc/role/{name}" endpoints ([#488](https://github.com/terraform-providers/terraform-provider-vault/pull/488)).
* Adds a resource for the "/transit/keys/{name}" endpoint ([#477](https://github.com/terraform-providers/terraform-provider-vault/pull/477)).
* Adds a resource for the "/sys/mfa/method/duo/{name}" endpoint ([#443](https://github.com/terraform-providers/terraform-provider-vault/pull/443)).
* Adds a resource for the "/azure/config" endpoint ([#481](https://github.com/terraform-providers/terraform-provider-vault/pull/481)).

IMPROVEMENTS:

* Adds a lock to prevent races in identity group resources ([#492](https://github.com/terraform-providers/terraform-provider-vault/pull/492) and [#495](https://github.com/terraform-providers/terraform-provider-vault/pull/495)).
* Adds support for new common token fields on roles that were introduced in Vault 1.2.0 ([#478](https://github.com/terraform-providers/terraform-provider-vault/pull/478) and [#487](https://github.com/terraform-providers/terraform-provider-vault/pull/487)).
* Adds the ability to run a coverage report to learn what Vault OpenAPI endpoints are and aren't supported ([#466](https://github.com/terraform-providers/terraform-provider-vault/pull/466)).
* Exposes the "local" flag on the `vault_mount` resource ([#462](https://github.com/terraform-providers/terraform-provider-vault/pull/462)).

BUG FIXES:

* `resource/aws_auth_backend_client`: Backend supports nested paths [#461]
* Adds "ForceNew" to the "groupname" parameter on the LDAP auth groups endpoint so if there's a change, the old group is deleted ([#465](https://github.com/terraform-providers/terraform-provider-vault/pull/465)).
* Fixes issue with a permanent diff in `vault_gcp_secret_roleset` ([#476](https://github.com/terraform-providers/terraform-provider-vault/pull/476)).

## 2.1.0 (July 05, 2019)

IMPROVEMENTS:

* For `aws_secret_backend_role`, adds support for `default_sts_ttl` and `max_sts_ttl` ([#444](https://github.com/terraform-providers/terraform-provider-vault/pull/444)).

BUG FIXES:

* Fixes ordering issues with `aws_auth_backend_role` and `aws_auth_backend_role_tags` ([#439](https://github.com/terraform-providers/terraform-provider-vault/pull/439)).
* Supports providing lists for `bound_claims` ([#455](https://github.com/terraform-providers/terraform-provider-vault/pull/455)).
* Resolves issue with persistent diffs on `vault_generic_secret` ([#456](https://github.com/terraform-providers/terraform-provider-vault/pull/456)).

## 2.0.0 (June 19, 2019)

FEATURES:

* Adds support for using the Vault provider with Terraform 0.12. See the [upgrade guide](https://www.terraform.io/docs/providers/vault/version_2_upgrade.html) ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))

BACKWARDS INCOMPATIBILITIES/NOTES:

* `all`: deprecated fields are now removed ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))
* `auth_backend`: the `path` field and `id` now no longer have a trailing slash ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))
* `database_secret_backend_role`: the `_statements` fields are now a list, not strings ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))
* `pki_secret_backend_config_urls`: the certificate fields are now lists, not strings ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))
* `pki_secret_backend_role`: the certificate fields are now lists, not strings ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))
* `pki_secret_backend_sign`: the `ca_chain` field is now a list, not a string ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))
* `rabbitmq_secret_backend_role`: the `vhosts` field is now a `vhost` block ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))

IMPROVEMENTS:

* `azure_auth_backend_role`: `client_secret` will now be set in state ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))

BUG FIXES:

* `namespace`: namespaces will now be removed from state instead of erroring when they're not found ([#446](https://github.com/terraform-providers/terraform-provider-vault/issues/446))


## 1.9.0 (June 12, 2019)

IMPROVEMENTS:

* Adds support for `role_arns` on `aws_secret_backend_role`([#407](https://github.com/terraform-providers/terraform-provider-vault/pull/407)).
* Updates the vendored version of Vault to 1.1.2 so features introduced since then can be added ([#413](https://github.com/terraform-providers/terraform-provider-vault/pull/413)).
* Implements `accessor` attribute on the Okta auth backend ([#420](https://github.com/terraform-providers/terraform-provider-vault/pull/420)).
* Allows the Vault token to be read from the environment ([#434](https://github.com/terraform-providers/terraform-provider-vault/pull/434)).
* Supports `project_id` and `bound_projects` in the GCP auth backend's roles ([#411](https://github.com/terraform-providers/terraform-provider-vault/pull/411)).

BUG FIXES:

* Fixes a case on `vault_aws_auth_backend_role` where `resolve_aws_unique_ids` could not be updated from `true` to `false` without recreating the resource ([#382](https://github.com/terraform-providers/terraform-provider-vault/pull/382)).
* Removes default TTL's from the GCP secret backend resource, letting them instead be set by Vault ([#426](https://github.com/terraform-providers/terraform-provider-vault/pull/426)).

## 1.8.0 (May 07, 2019)

FEATURES:

* Adds OIDC support to the JWT auth backend ([#398](https://github.com/terraform-providers/terraform-provider-vault/pull/398)).
* **New Resource**: Adds a `vault_pki_secret_backend_config_urls` resource ([#399](https://github.com/terraform-providers/terraform-provider-vault/pull/399)).

IMPROVEMENTS:

* Adds support for automatically renewing certificates in the PKI certs backend ([#386](https://github.com/terraform-providers/terraform-provider-vault/pull/386)).
* Adds support for `uri_sans` in the PKI secret backend ([#373](https://github.com/terraform-providers/terraform-provider-vault/pull/373)).
* Allows a user to delete all policies in the AWS auth role resource ([#395](https://github.com/terraform-providers/terraform-provider-vault/pull/395)).

BUG FIXES:

* Fixes the ability to handle JWT roles that lack policies ([#389](https://github.com/terraform-providers/terraform-provider-vault/pull/389)).
* Allows `vault_ldap_auth` resources to be imported ([#387](https://github.com/terraform-providers/terraform-provider-vault/pull/387)).
* Fixes issue with trailing slashes for the Vault namespaces resource ([#391](https://github.com/terraform-providers/terraform-provider-vault/pull/391)).
* Fixes a bug with namespaces where the path was being overwritten ([#396](https://github.com/terraform-providers/terraform-provider-vault/pull/396)).

## 1.7.0 (April 03, 2019)

FEATURES:

* **New Resource**: Adds a "Flexible Generic Secret" resource so it can be used to consume Vault APIs that don't yet have a resource ([#244](https://github.com/terraform-providers/terraform-provider-vault/pull/244)).
* **New Resource**: Adds a token resource ([#337](https://github.com/terraform-providers/terraform-provider-vault/pull/337)).
* **New Resource**: Adds a GCP secret roleset resource ([#312](https://github.com/terraform-providers/terraform-provider-vault/pull/312)).
* **New Resource**: Adds a `vault_identity_group_policies` resource ([#321](https://github.com/terraform-providers/terraform-provider-vault/pull/321)).

IMPROVEMENTS:

* For the LDAP auth method, adds support for the `use_token_groups` field ([#367](https://github.com/terraform-providers/terraform-provider-vault/pull/367)).
* Adds the ability to set `max_retries` on the Vault client ([#355](https://github.com/terraform-providers/terraform-provider-vault/pull/355)).
* For the Github auth method, adds support for the `accessor` field ([#350](https://github.com/terraform-providers/terraform-provider-vault/pull/350)).
* For the generic secrets resource, adds support for a `data` field ([#330](https://github.com/terraform-providers/terraform-provider-vault/pull/330)).
* For the JWT auth backend, adds support for a `groups_claim_delimiter_pattern` on roles ([#296](https://github.com/terraform-providers/terraform-provider-vault/pull/296)).
* For the JWT auth backend, adds a `role_type` field ([#317](https://github.com/terraform-providers/terraform-provider-vault/pull/317)).
* For the JWT auth backend, adds a `jwt_supported_algs` field ([#345](https://github.com/terraform-providers/terraform-provider-vault/pull/345)).

BUG FIXES:

* Fixes TTL parsing on PKI certificate creation ([#314](https://github.com/terraform-providers/terraform-provider-vault/pull/314)).
* Fixes ability to update the `data` field on database secrets engine connections ([#340](https://github.com/terraform-providers/terraform-provider-vault/pull/340)).
* Unmarks `policy_document` and `policy_arns` from being in conflict with each other ([#344](https://github.com/terraform-providers/terraform-provider-vault/pull/344)).

## 1.6.0 (March 06, 2019)

FEATURES:

* Adds compatibility with Vault 1.0 ([#292](https://github.com/terraform-providers/terraform-provider-vault/pull/292)).
* **New Resource**: Supports the SSH secrets engine role endpoint ([#285](https://github.com/terraform-providers/terraform-provider-vault/pull/285), [#303](https://github.com/terraform-providers/terraform-provider-vault/pull/303), and [#331](https://github.com/terraform-providers/terraform-provider-vault/pull/331)).
* **New Data Source**: Adds a `vault_policy_document` data source ([#283](https://github.com/terraform-providers/terraform-provider-vault/pull/283)).
* **New Resource**: Adds a namespace resource ([#338](https://github.com/terraform-providers/terraform-provider-vault/pull/338)).

IMPROVEMENTS:

* Adds [a guide for how to contribute](https://github.com/terraform-providers/terraform-provider-vault/blob/master/.github/CONTRIBUTING.md) in the least iterations possible.
* For the TLS Certificates auth method, adds support for the following role fields: `allowed_common_names`, `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, and `allowed_organization_units` ([#282](https://github.com/terraform-providers/terraform-provider-vault/pull/282)).
* For the GCP auth method, adds support for the following role fields: `add_group_aliases`, `max_jwt_exp`, and `allow_gce_inference` ([#308](https://github.com/terraform-providers/terraform-provider-vault/pull/308) and [#318](https://github.com/terraform-providers/terraform-provider-vault/pull/318)).
* For the Kubernetes auth method, adds support for `bound_cidrs` ([#305](https://github.com/terraform-providers/terraform-provider-vault/pull/305)).
* For `vault_identity_group`, fixes issue with `policies` not being updated properly ([#301](https://github.com/terraform-providers/terraform-provider-vault/pull/301)).
* For the AWS secret engine, updates to the current role fields ([#323](https://github.com/terraform-providers/terraform-provider-vault/pull/323)).

BUG FIXES:

* Marks the `token_reviewer_jwt` sensitive ([#282](https://github.com/terraform-providers/terraform-provider-vault/pull/282)).
* Fixes an issue where boolean parameters were not set when the value was false in the AWS role resource ([#302](https://github.com/terraform-providers/terraform-provider-vault/pull/302)).
* Guards for a nil CA chain in `resource_pki_secret_backend_cert` ([#310](https://github.com/terraform-providers/terraform-provider-vault/pull/310)).

## 1.5.0 (January 30, 2019)

FEATURES:

* Adds support for namespaces ([#262](https://github.com/terraform-providers/terraform-provider-vault/pull/262/files))
* Adds support for EGP and RGP, a.k.a. Sentinel ([#264](https://github.com/terraform-providers/terraform-provider-vault/pull/264))
* **New Resource**: Supports the PKI secrets backend ([#158](https://github.com/terraform-providers/terraform-provider-vault/pull/158))
* **New Resource**: Supports identity entities and entity aliases ([#247](https://github.com/terraform-providers/terraform-provider-vault/pull/247) and [#287](https://github.com/terraform-providers/terraform-provider-vault/pull/287))
* **New Resource**: Supports Github auth backend ([#255](https://github.com/terraform-providers/terraform-provider-vault/pull/255))
* **New Resource**: Supports Azure auth backend ([#275](https://github.com/terraform-providers/terraform-provider-vault/pull/275))
* **New Resource**: Supports JWT auth backend ([#272](https://github.com/terraform-providers/terraform-provider-vault/pull/272))

BUG FIXES:

* Fixes a panic related to `max_connection_lifetime` parameters in the database secrets backends ([#250](https://github.com/terraform-providers/terraform-provider-vault/pull/250))
* Fixes issue where the `role_name` on `token_auth_backend_role` would not be updated ([#279](https://github.com/terraform-providers/terraform-provider-vault/pull/279))
* Fixes wrong response data from `gcp_auth_backend_role` ([#243](https://github.com/terraform-providers/terraform-provider-vault/pull/243))

## 1.4.1 (December 14, 2018)

BUG FIXES:

* Fixes an issue with database resources where db statements were overwritten when not provided ([#260](https://github.com/terraform-providers/terraform-provider-vault/pull/260))

## 1.4.0 (December 11, 2018)

FEATURES:

* **New Resource**: `vault_gcp_auth_backend` ([#198](https://github.com/terraform-providers/terraform-provider-vault/pull/198))
* **New Resource**: `vault_identity_group` ([#220](https://github.com/terraform-providers/terraform-provider-vault/pull/220))
* **New Resource**: `vault_identity_group_alias` ([#220](https://github.com/terraform-providers/terraform-provider-vault/pull/220))

IMPROVEMENTS:

* Makes `gcp_secret_backend` credentials optional ([#239](https://github.com/terraform-providers/terraform-provider-vault/pull/239))
* Adds more configuration parameters for `auth_backend` ([#245](https://github.com/terraform-providers/terraform-provider-vault/pull/245))

BUG FIXES:

* Fixes issue with `vault_database_secret_backend_connection` always updating the connection URL ([#217](https://github.com/terraform-providers/terraform-provider-vault/pull/217))

## 1.3.1 (November 06, 2018)

BUG FIXES:

* Solves issue where the incorrect KV store was selected for older Vault versions as described in [#229](https://github.com/terraform-providers/terraform-provider-vault/issues/229).

## 1.3.0 (November 05, 2018)

FEATURES:

* **New Resource**: Supports KV V2 ([#156](https://github.com/terraform-providers/terraform-provider-vault/pull/156))
* **New Resource**: `vault_gcp_secret_backend` ([#212](https://github.com/terraform-providers/terraform-provider-vault/pull/212))
* **New Resource**: `vault_aws_auth_backend_roletag_blacklist` ([#27](https://github.com/terraform-providers/terraform-provider-vault/pull/27))
* **New Resources**: `vault_rabbitmq_secret_backend` and `vault_rabbitmq_secret_backend_role` ([#216](https://github.com/terraform-providers/terraform-provider-vault/pull/216))

IMPROVEMENTS:

* Adds `bound_zones`, `bound_regions`, `bound_instance_groups`, and `bound_labels` for GCP auth roles via [#227](https://github.com/terraform-providers/terraform-provider-vault/pull/227)
* Exports the LDAP auth backend `accessor` via [#195](https://github.com/terraform-providers/terraform-provider-vault/pull/195)
* Allows for templated database backends via [#168](https://github.com/terraform-providers/terraform-provider-vault/pull/168)

BUG FIXES:

* [#222](https://github.com/terraform-providers/terraform-provider-vault/pull/222) ensures that booleans on AWS roles default to values matchiing Vault's defaults

## 1.2.0 (October 26, 2018)

FEATURES:

* **New Resource**: `vault_jwt_auth_backend_role` ([#188](https://github.com/terraform-providers/terraform-provider-vault/pull/188))
* **New Resources**: `vault_kubernetes_auth_backend_config` and `vault_kubernetes_auth_backend_role` ([#94](https://github.com/terraform-providers/terraform-provider-vault/pull/94))
* **New Resource**: `vault_ssh_secret_backend_ca` ([#163](https://github.com/terraform-providers/terraform-provider-vault/pull/163))
* **New Feature**: Support for the Vault token helper ([#136](https://github.com/terraform-providers/terraform-provider-vault/pull/136))

IMPROVEMENTS:

* Re-adds changes to `vault_aws_auth_backend_role` from [#53](https://github.com/terraform-providers/terraform-provider-vault/pull/153)
* Adds backwards compatibility for the above via [#189](https://github.com/terraform-providers/terraform-provider-vault/pull/189)
* Adds `bound_ec2_instance_id` to `vault_aws_auth_backend_role` ([#135](https://github.com/terraform-providers/terraform-provider-vault/pull/135))
* Adds `mysql_rds`, `mysql_aurora`, and `mysql_legacy` to the MySQL backend via [#87](https://github.com/terraform-providers/terraform-provider-vault/pull/87)
* Makes audit device path optional via [#180](https://github.com/terraform-providers/terraform-provider-vault/pull/180)
* Adds the field `accessor` to `resource_auth_backend` and `resource_mount` via [#150](https://github.com/terraform-providers/terraform-provider-vault/pull/150)
* Marks `bindpass` as sensitive in the `vault_ldap_auth_backend` ([#184](https://github.com/terraform-providers/terraform-provider-vault/pull/184))


BUG FIXES:

* Fixes inablity to destroy a secret ID after consumption ([#97](https://github.com/terraform-providers/terraform-provider-vault/issues/97)) via [#148](https://github.com/terraform-providers/terraform-provider-vault/pull/148)

## 1.1.4 (September 20, 2018)

BUG FIXES:

* Reverts breaking changes to `vault_aws_auth_backend_role` introduced by ([#53](https://github.com/terraform-providers/terraform-provider-vault/pull/153))

## 1.1.3 (September 18, 2018)

FEATURES:

* **New Resource**: `vault_consul_secret_backend` ([#59](https://github.com/terraform-providers/terraform-provider-vault/pull/59))
* **New Resource**: `vault_cert_auth_backend_role` ([#123](https://github.com/terraform-providers/terraform-provider-vault/pull/123))
* **New Resource**: `vault_gcp_auth_backend_role` ([#124](https://github.com/terraform-providers/terraform-provider-vault/pull/124))
* **New Resource**: `vault_ldap_auth_backend` ([#126](https://github.com/terraform-providers/terraform-provider-vault/pull/126))
* **New Resource**: `vault_ldap_auth_backend_user` ([#126](https://github.com/terraform-providers/terraform-provider-vault/pull/126))
* **New Resource**: `vault_ldap_auth_backend_group` ([#126](https://github.com/terraform-providers/terraform-provider-vault/pull/126))

## 1.1.2 (September 14, 2018)

FEATURES:

* **New Resource**: `vault_audit` ([#81](https://github.com/terraform-providers/terraform-provider-vault/pull/81))
* **New Resource**: `vault_token_auth_backend_role` ([#80](https://github.com/terraform-providers/terraform-provider-vault/pull/80))

UPDATES:
* Update to vendoring Vault 0.11.1. Introduces some breaking changes for some back ends so update with care.

## 1.1.1 (July 23, 2018)

BUG FIXES:
* Fix panic in `vault_approle_auth_backend_role` when used with Vault 0.10 ([#103](https://github.com/terraform-providers/terraform-provider-vault/issues/103))

## 1.1.0 (April 09, 2018)

FEATURES:

* **New Resource**: `vault_okta_auth_backend` ([#8](https://github.com/terraform-providers/terraform-provider-vault/issues/8))
* **New Resource**: `vault_okta_auth_backend_group` ([#8](https://github.com/terraform-providers/terraform-provider-vault/issues/8))
* **New Resource**: `vault_okta_auth_backend_user` ([#8](https://github.com/terraform-providers/terraform-provider-vault/issues/8))
* **New Resource**: `vault_approle_auth_backend_login` ([#34](https://github.com/terraform-providers/terraform-provider-vault/issues/34))
* **New Resource**: `vault_approle_auth_backend_role_secret_id` ([#31](https://github.com/terraform-providers/terraform-provider-vault/issues/31))
* **New Resource**: `vault_database_secret_backend_connection` ([#37](https://github.com/terraform-providers/terraform-provider-vault/issues/37))

BUG FIXES:

* Fix bug in `policy_arn` parameter of `vault_aws_secret_backend_role` ([#49](https://github.com/terraform-providers/terraform-provider-vault/issues/49))
* Fix panic in `vault_generic_secret` when reading a missing secret ([#55](https://github.com/terraform-providers/terraform-provider-vault/issues/55))
* Fix bug in `vault_aws_secret_backend_role` preventing use of nested paths ([#79](https://github.com/terraform-providers/terraform-provider-vault/issues/79))
* Fix bug in `vault_aws_auth_backend_role` that failed to update the role name when it changed ([#86](https://github.com/terraform-providers/terraform-provider-vault/issues/86))

## 1.0.0 (November 16, 2017)

BACKWARDS INCOMPATIBILITIES / NOTES:
* `vault_auth_backend`'s ID has changed from the `type` to the `path` of the auth backend.
  Interpolations referring to the `.id` of a `vault_auth_backend` should be updated to use
  its `.type` property. ([#12](https://github.com/terraform-providers/terraform-provider-vault/issues/12))
* `vault_generic_secret`'s `allow_read` field is deprecated; use `disable_read` instead.
  If `disable_read` is set to false or not set, the secret will be read.
  If `disable_read` is true and `allow_read` is false or not set, the secret will not be read.
  If `disable_read` is true and `allow_read` is true, the secret will be read. ([#17](https://github.com/terraform-providers/terraform-provider-vault/issues/17))

FEATURES:
* **New Data Source**: `aws_access_credentials` ([#20](https://github.com/terraform-providers/terraform-provider-vault/issues/20))
* **New Resource**: `aws_auth_backend_cert` ([#21](https://github.com/terraform-providers/terraform-provider-vault/issues/21))
* **New Resource**: `aws_auth_backend_client` ([#19](https://github.com/terraform-providers/terraform-provider-vault/issues/19))
* **New Resource**: `aws_auth_backend_login` ([#28](https://github.com/terraform-providers/terraform-provider-vault/issues/28))
* **New Resource**: `aws_auth_backend_role` ([#24](https://github.com/terraform-providers/terraform-provider-vault/issues/24))
* **New Resource**: `aws_auth_backend_sts_role` ([#22](https://github.com/terraform-providers/terraform-provider-vault/issues/22))

IMPROVEMENTS:
* `vault_auth_backend`s are now importable. ([#12](https://github.com/terraform-providers/terraform-provider-vault/issues/12))
* `vault_policy`s are now importable ([#15](https://github.com/terraform-providers/terraform-provider-vault/issues/15))
* `vault_mount`s are now importable ([#16](https://github.com/terraform-providers/terraform-provider-vault/issues/16))
* `vault_generic_secret`s are now importable ([#17](https://github.com/terraform-providers/terraform-provider-vault/issues/17))

BUG FIXES:

## 0.1.0 (June 21, 2017)

NOTES:
