## 1.4.2 (Unreleased)

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
