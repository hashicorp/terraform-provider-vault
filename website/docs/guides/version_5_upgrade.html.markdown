---
layout: "vault"
page_title: "Terraform Vault Provider 5.X Upgrade Guide"
sidebar_current: "docs-vault-provider-version-5-upgrade"
description: |-
  Terraform Vault Provider 5.X Upgrade Guide

---

# Terraform Vault Provider 5.X Upgrade Guide

Version `5.X` of the Vault provider for Terraform is a major release and
includes some changes that you will need to consider when upgrading. This guide
is intended to help with that process and focuses only on the changes necessary
to upgrade from version `4.X` to `5.X`.

Most of the changes outlined in this guide have been previously marked as
deprecated in the Terraform `plan`/`apply` output throughout previous provider
releases, up to and including 4.8.0. These changes, such as deprecation notices,
can always be found in the [CHANGELOG](https://github.com/hashicorp/terraform-provider-vault/blob/master/CHANGELOG.md).

-> If you are upgrading from `1.9.x`. Please follow the
[2.0.0 Upgrade Guide](./version_2_upgrade.html) before proceeding any further.

-> If you are upgrading from `2.24.X`. Please follow the
[3.0.0 Upgrade Guide](./version_3_upgrade.html) before proceeding any further.

-> If you are upgrading from `3.25.X`. Please follow the
[4.0.0 Upgrade Guide](./version_4_upgrade.html) before proceeding any further.

## Why version 5.X?

We introduced version `5.X` in order to multiplex the provider
to use the [Terraform Plugin Framework](https://developer.hashicorp.com/terraform/plugin/framework),
upgrade to Terraform `1.11.x`, and support Ephemeral Resources and Write-Only attributes.
The change was deemed significant enough to warrant the major version bump.
In addition to the aforementioned Framework upgrade, previously deprecated fields have been removed.

While you may see some small changes in your configurations as a result of
these changes, we don't expect you'll need to make any major refactorings.

## What Vault server versions are supported in version 5.X?

The Vault provider will be dropping Vault version support for Vault <= `1.13.x`.
This means that only Vault server version `1.14.x` and greater will be supported.

## Which Terraform versions are supported?

In order to support Ephemeral resources and Write-Only attributes, Terraform versions `1.11.x `
and greater are fully supported.

Please see the [Terraform Upgrade Guide](https://www.terraform.io/upgrade-guides/index.html)
for more info about upgrading Terraform.

## I accidentally upgraded to 5.X, how do I downgrade to 4.X?

If you've inadvertently upgraded to `5.X`, first see the
[Provider Version Configuration Guide](#provider-version-configuration) to lock
your provider version; if you've constrained the provider to a lower version
such as shown in the previous version example in that guide, Terraform will pull
in a `4.X` series release on `terraform init`.

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
- [Provider: `address`](#provider-address)
- [Provider: `token`](#provider-token)
- [Resource: `vault_kv_secret_v2`](#resource-vault_kv_secret_v2)
- [Deprecated Field Removals](#deprecated-field-removals)
    - [Okta Auth Backend](#okta-auth-backend)
        - [`ttl`](#okta-secret-backend)
        - [`max_ttl`](#okta-secret-backend)

<!-- /TOC -->

## Provider Version Configuration

-> Before upgrading to version `5.X`, it is recommended to upgrade to the most
recent version of the provider (`4.8.0`) and ensure that your environment
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

  version = "~> 4.8.0"
}
```

An updated configuration:

```hcl
provider "vault" {
  # ... other configuration ...

  version = "~> 5.0.0"
}
```

## Provider: `address`
This field will no longer be requested via input if unset, but the provider will still error
if it is not set in the config or via the environment variable `VAULT_ADDR`.

## Provider: `token`
This field will no longer be requested via input if unset, but the provider will still error
if it is not set in the config or via the environment variable `VAULT_TOKEN`.


## Resource: `vault_kv_secret_v2`

*BREAKING CHANGE*
With the addition of an ephemeral resource and write-only attributes for KVV2, this resource will maintain the 
KVV2 engine in Vault as the source of truth, and will no longer store/track the secret data in the Terraform state.

This resource will still store metadata and other parameters on the secret, but not the secret itself:
* `data` - This computed attribute has been deprecated, and will no longer be set to the TF state. Please use the
  new ephemeral resource `vault_kv_secret_v2` to read the secret back from Vault to reference in other resources.

* `data_json` - Drifts in this value outside of Terraform will no longer be read from Vault and tracked in the TF state. 
  It is also recommended to switch to using the new write-only attributes `data_json_wo` and `data_json_wo_version` to avoid 
  leaking the secret data to the TF state.


## Deprecated Field Removals

The following deprecated fields have been removed:

### Okta Auth Backend

* `ttl` - removed from the `vault_okta_auth_backend` resource.

* `max_ttl` - removed from the `vault_okta_auth_backend` resource.