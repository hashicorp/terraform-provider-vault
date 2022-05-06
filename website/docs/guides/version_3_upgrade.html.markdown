---
layout: "vault"
page_title: "Terraform Vault Provider 3.0.0 Upgrade Guide"
sidebar_current: "docs-vault-provider-version-3-upgrade"
description: |-
  Terraform Vault Provider 3.0.0 Upgrade Guide

---

# Terraform Vault Provider 3.0.0 Upgrade Guide

Version `3.0.0` of the Vault provider for Terraform is a major release and
includes some changes that you will need to consider when upgrading. This guide
is intended to help with that process and focuses only on the changes necessary
to upgrade from version `2.24.0` to `3.0.0`.

Most of the changes outlined in this guide have been previously marked as
deprecated in the Terraform `plan`/`apply` output throughout previous provider
releases, up to and including 2.24.0. These changes, such as deprecation notices,
can always be found in the [CHANGELOG](https://github.com/hashicorp/terraform-provider-vault/blob/master/CHANGELOG.md).

-> If you are upgrading from `1.9.x`. Please follow the
[2.0.0 Upgrade Guide](./version_2_upgrade.html) before proceeding any further.

## Why version 3.0.0?

We introduced version `3.0.0` of the Vault provider in order to upgrade to the
[Terraform Plugin SDKv2](https://www.terraform.io/docs/extend/sdkv2-intro.html).
The change was deemed significant enough to warrant the major version bump.
In addition to the aforementioned SDK upgrade all previously deprecated fields,
and resources have been removed.

While you may see some small changes in your configurations as a result of
these changes, we don't expect you'll need to make any major refactorings.

## Which Terraform versions are supported?

Terraform versions `0.12.x` and greater are fully supported. Support for `0.11.x` has been removed.
If you are still on one of the `0.11.x` versions we recommend upgrading to the latest stable release of Terraform.

Please see the [Terraform Upgrade Guide](https://www.terraform.io/upgrade-guides/index.html)
for more info about upgrading Terraform.

## I accidentally upgraded to 3.0.0, how do I downgrade to `2.X`?

If you've inadvertently upgraded to `3.0.0`, first see the
[Provider Version Configuration Guide](#provider-version-configuration) to lock
your provider version; if you've constrained the provider to a lower version
such as shown in the previous version example in that guide, Terraform will pull
in a `2.X` series release on `terraform init`.

If you've only run `terraform init` or `terraform plan`, your state will not
have been modified and downgrading your provider is sufficient.

If you've run `terraform refresh` or `terraform apply`, Terraform may have made
state changes in the meantime.

- If you're using a *local* state, `terraform refresh` with a downgraded
  provider is likely sufficient to revert your state.
- If you're using a *remote* state backend
  - That does not support versioning, see the local state instructions above
  - That supports *versioning* you can revert the Terraform state file to a previous
    version by hand. If you do so and Terraform created resources as part of a
    `terraform apply`, you'll need to either `terraform import` them or delete
    them by hand.

## Upgrade Topics

<!-- TOC depthFrom:2 depthTo:2 -->

- [Provider Version Configuration](#provider-version-configuration)

- [Data Source: `vault_kubernetes_auth_backend_role`](#data-source-vault_kubernetes_auth_backend_role)

- [Resource: `vault_approle_auth_backend_role`](#resource-vault_approle_auth_backend_role)
- [Resource: `vault_auth_backend`](#resource-vault_auth_backend)
- [Resource: `vault_aws_auth_backend_role`](#resource-vault_aws_auth_backend_role)
- [Resource: `vault_azure_auth_backend_role`](#resource-vault_azure_auth_backend_role)
- [Resource: `vault_cert_auth_backend_role`](#resource-vault_cert_auth_backend_role)
- [Resource: `vault_consul_secret_backend_role`](#resource-vault_consul_secret_backend_role)
- [Resource: `vault_gcp_auth_backend_role`](#resource-vault_gcp_auth_backend_role)
- [Resource: `vault_generic_secret`](#resource-vault_generic_secret)
- [Resource: `vault_github_auth_backend`](#resource-vault_github_auth_backend)
- [Resource: `vault_jwt_auth_backend_role`](#resource-vault_jwt_auth_backend_role)
- [Resource: `vault_kubernetes_auth_backend_role`](#resource-vault_kubernetes_auth_backend_role)
- [Resource: `vault_pki_secret_backend`](#resource-vault_pki_secret_backend)
- [Resource: `vault_token`](#resource-vault_token)
- [Resource: `vault_token_auth_backend_role`](#resource-vault_token_auth_backend_role)

<!-- /TOC -->

## Provider Version Configuration

-> Before upgrading to version `3.0.0`, it is recommended to upgrade to the most
recent version of the provider (`2.24.0`) and ensure that your environment
successfully runs [`terraform plan`](https://www.terraform.io/docs/commands/plan.html)
without unexpected changes or deprecation notices.

It is recommended to use [version constraints](https://www.terraform.io/docs/configuration/providers.html#provider-versions)
when configuring Terraform providers. If you are following that recommendation,
update the version constraints in your Terraform configuration and run
[`terraform init`](https://www.terraform.io/docs/commands/init.html) to download
the new version.

If you aren't using version constraints, you can use `terraform init -upgrade`
in order to upgrade your provider to the latest released version.

For example, given this previous configuration:

```hcl
provider "vault" {
  # ... other configuration ...

  version = "~> 2.24.0"
}
```

An updated configuration:

```hcl
provider "vault" {
  # ... other configuration ...

  version = "~> 3.0.0"
}
```

## Data Source: `vault_kubernetes_auth_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `bound_cidrs` - use `token_bound_cidrs` instead.

* `ttl` - use `token_ttl` instead.

* `max_ttl` - use `token_max_ttl` instead.

* `policies` - use `token_policies` instead.

* `period` - use `token_period` instead.

* `num_uses` - use `token_num_uses` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_approle_auth_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `bound_cidr_list` - use `secret_id_bound_cidrs` instead.

* `policies` - use `token_policies` instead.

* `period` - use `token_period` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_auth_backend`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `default_lease_ttl_seconds` - use `tune.default_lease_ttl` instead.

* `max_lease_ttl_seconds` - use `tune.max_lease_ttl` instead.

* `listing_visibility` - use `tune.listing_visibility` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_aws_auth_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `ttl` - use `token_ttl` instead.

* `max_ttl` - use `token_max_ttl` instead.

* `policies` - use `token_policies` instead.

* `period` - use `token_period` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_azure_auth_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `ttl` - use `token_ttl` instead.

* `max_ttl` - use `token_max_ttl` instead.

* `policies` - use `token_policies` instead.

* `period` - use `token_period` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_cert_auth_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `bound_cidrs` - use `token_bound_cidrs` instead.

* `ttl` - use `token_ttl` instead.

* `max_ttl` - use `token_max_ttl` instead.

* `policies` - use `token_policies` instead.

* `period` - use `token_period` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_consul_secret_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `path` - use `backend` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_gcp_auth_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `project_id` - use `bound_projects` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_generic_secret`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `allow_read` - use `disable_read` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_github_auth_backend`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `ttl` - use `token_ttl` instead.

* `max_ttl` - use `token_max_ttl` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_jwt_auth_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `groups_claim_delimiter_pattern` - no alternate exists.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_kubernetes_auth_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `num_uses` - use `token_num_uses` instead.

* `ttl` - use `token_ttl` instead.

* `max_ttl` - use `token_max_ttl` instead.

* `policies` - use `token_policies` instead.

* `period` - use `token_period` instead.

* `bound_cidrs` - use `token_bound_cidrs` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_pki_secret_backend`

### Deprecated resource
-> This resource has been replaced by [vault_mount](../r/mount.html).

A replacement might look like:

```hcl
resource "vault_mount" "pki-example" {
  path        = "pki-example"
  type        = "pki"
  description = "This is an example PKI mount"

  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}
```

_Attempting to provision a `vault_pki_secret_backend` resource will raise an error._

## Resource: `vault_token`

### Removed fields
The following fields have been removed as they are no longer supported by the [Terraform Plugin SDK](https://www.terraform.io/docs/extend/guides/v2-upgrade-guide.html#removal-of-helper-encryption-package).
Please see [Sensitive State Best Practices](https://www.terraform.io/docs/extend/best-practices/sensitive-state.html#don-39-t-encrypt-state) for more info.

* `encrypted_client_token` - removed.
 
* `pgp_key` - removed

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._

## Resource: `vault_token_auth_backend_role`

### Deprecated fields have been removed
The following deprecated fields have been removed:

* `explicit_max_ttl` use `token_explicit_max_ttl` instead.

* `period` - use `token_period` instead.

* `bound_cidrs` - use `token_bound_cidrs` instead.

_Specifying any of the fields above in your config or trying to interpolate them in your config will raise an error._
