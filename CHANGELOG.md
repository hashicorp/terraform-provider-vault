## 1.1.1 (Unreleased)

BUG FIXES:
* Fix panic in `vault_approle_auth_backend_role` when used with Vault 0.10 [GH-103]

FEATURES:

* **New Resource**: `vault_consul_secret_engine_role`

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
