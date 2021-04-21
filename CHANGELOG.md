## 2.19.1 (Unreleased)

SECURITY:
* `resource/vault_gcp_auth_backend_role`: Fixed typo in `bound_labels` parameter name causing no values to be applied to created roles [CVE-2021-30476](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30476) ([#1028](https://github.com/hashicorp/terraform-provider-vault/pull/1002))

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

* Same functionality as that of Terraform 0.9.8. Repacked as part of [Provider Splitout](https://www.hashicorp.com/blog/upcoming-provider-changes-in-terraform-0-10/)
