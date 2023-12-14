---
layout: "vault"
page_title: "Terraform Vault Provider 4.0.0 Upgrade Guide"
sidebar_current: "docs-vault-provider-version-4-upgrade"
description: |-
  Terraform Vault Provider 4.0.0 Upgrade Guide

---

# Terraform Vault Provider 4.0.0 Upgrade Guide

Version `4.0.0` of the Vault provider for Terraform is a major release and
includes some changes that you will need to consider when upgrading. This guide
is intended to help with that process and focuses only on the changes necessary
to upgrade from version `3.24.0` to `4.0.0`.

Most of the changes outlined in this guide have been previously marked as
deprecated in the Terraform `plan`/`apply` output throughout previous provider
releases, up to and including 3.24.0. These changes, such as deprecation notices,
can always be found in the [CHANGELOG](https://github.com/hashicorp/terraform-provider-vault/blob/master/CHANGELOG.md).

## Why version 4.0.0?

We introduced version `4.0.0` of the Vault provider in order to upgrade to the
[Terraform Plugin Framework](https://developer.hashicorp.com/terraform/plugin/framework).
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

## I accidentally upgraded to 4.0.0, how do I downgrade to `3.X`?

If you've inadvertently upgraded to `4.0.0`, first see the
[Provider Version Configuration Guide](#provider-version-configuration) to lock
your provider version; if you've constrained the provider to a lower version
such as shown in the previous version example in that guide, Terraform will pull
in a `3.X` series release on `terraform init`.

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

- [Provider `address` Field Changes](#provider-address-field-changes)

- [Provider Field Removals](#provider-field-removals)

- [Environment Variable Removals](#environment-variable-removals)

- [Deprecated Field Removals](#deprecated-field-removals)

  - [Cert Auth Backend: `allowed_organization_units`](#cert-auth-backend-role)
  - [LDAP Secret Backend: `length`](#ldap-secret-backend)
  - [Transit Secret Backend Key: `auto_rotate_interval`](#transit-secret-backend-key)
  - [SSH Backend Role: `allowed_user_key_lengths`](#ssh-backend-role)
  - [Consul Backend Role: `token_type`](#console-backend-role)
  - [PKI Root Cert: `serial`](#pki-root-cert)
  - [PKI Root Sign Intermediate: `serial`](#pki-root-sign-intermediate)
  - [PKI Root Sign: `serial`](#pki-sign)

<!-- /TOC -->

## Provider Version Configuration

-> Before upgrading to version `4.0.0`, it is recommended to upgrade to the most
recent version of the provider (`3.24.0`) and ensure that your environment
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

  version = "~> 3.24.0"
}
```

An updated configuration:

```hcl
provider "vault" {
  # ... other configuration ...

  version = "~> 4.0.0"
}
```

## Provider `address` Field Changes

The `address` field will no longer be requested via input if it is unset.

In previous versions of the Vault provider, if the Vault server address was unset
either in the `address` field of the provider block or the `VAULT_ADDR`
environment variable, the provider would request the Vault server address as
input.  As of `4.0.0`, the `address` field will no longer be requested via
input if it is unset.

If the Vault address is not set in the config or environment, the following
error will be returned:

```
Error: failed to configure Vault address
```

## Provider Field Removals

The following provider fields have been removed:

* `set_namespace_from_token` - use the environment variable
  `VAULT_SET_NAMESPACE_FROM_TOKEN` instead. Only accepts values of `true`
  or `false`.

* `client_auth` - use `auth_login_cert` instead.

## Environment Variable Removals

The following environment variables have been removed:

* `TERRAFORM_VAULT_SKIP_CHILD_TOKEN` - use the `skip_child_token` field instead.

* `VAULT_SKIP_VERIFY` - use the `skip_tls_verify` field instead.

## Deprecated Field Removals

The following deprecated fields have been removed:

### Cert Auth Backend Role

* `allowed_organization_units` - removed from the `vault_cert_auth_backend_role` resource.

### LDAP Secret Backend

* `length` - removed from the `vault_ldap_secret_backend` resource.

### Transit Secret Backend Key

* `auto_rotate_interval` - removed from the `vault_transit_secret_backend_key`
  resource. Use `auto_rotate_period` instead.

### SSH Backend Role

* `allowed_user_key_lengths` - removed from the `vault_ssh_secret_backend_role`
  resource. Use `allowed_user_key_config` instead.

### Consul Backend Role

* `token_type` - removed from the `vault_consul_secret_backend_role` resource.

### PKI Root Cert

* `serial` - removed from the `vault_pki_secret_backend_root_cert` resource. Use `serial_number` instead.

### PKI Root Sign Intermediate

* `serial` - removed from the `vault_pki_secret_backend_root_sign_intermediate` resource. Use `serial_number` instead.

### PKI Root Sign

* `serial` - removed from the `vault_pki_secret_backend_sign` resource. Use `serial_number` instead.
