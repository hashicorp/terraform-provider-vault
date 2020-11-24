---
layout: "vault"
page_title: "Terraform Vault Provider 2.0.0 Upgrade Guide"
sidebar_current: "docs-vault-provider-version-2-upgrade"
description: |-
  Terraform Vault Provider 2.0.0 Upgrade Guide

---

# Terraform Vault Provider 2.0.0 Upgrade Guide

Version `2.0.0` of the Vault provider for Terraform is a major release and
includes some changes that you will need to consider when upgrading. This guide
is intended to help with that process and focuses only on the changes necessary
to upgrade from version `1.9.0` to `2.0.0`.

Most of the changes outlined in this guide have been previously marked as
deprecated in the Terraform `plan`/`apply` output throughout previous provider
releases, up to and including 1.9.0. These changes, such as deprecation notices,
can always be found in the [CHANGELOG](https://github.com/hashicorp/terraform-provider-vault/blob/master/CHANGELOG.md).

Version 2.0.0 of the Vault provider is the first version to offer compatibility with
Terraform 0.12.

## Why version 2.0.0?

We introduced version `2.0.0` of the Vault provider in order to correct some bugs
that were affecting the provider and had no backwards-compatible solutions.
These bugs largely revolved around API types changing and our config structure
changing to match, or changing the format we store strings in state.

While you may see some small changes in your configurations as a result of
these changes, we don't expect you'll need to make any major refactorings.

## I accidentally upgraded to 2.0.0, how do I downgrade to `1.X`?

If you've inadvertently upgraded to `2.0.0`, first see the
[Provider Version Configuration Guide](#provider-version-configuration) to lock
your provider version; if you've constrained the provider to a lower version
such as shown in the previous version example in that guide, Terraform will pull
in a `1.X` series release on `terraform init`.

If you've only ran `terraform init` or `terraform plan`, your state will not
have been modified and downgrading your provider is sufficient.

If you've ran `terraform refresh` or `terraform apply`, Terraform may have made
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
- [Data Sources](#data-sources)
- [Resource: `vault_auth_backend`](#resource-vault-auth-backend)
- [Resource: `vault_aws_auth_backend_role`](#resource-vault-aws-auth-backend-role)
- [Resource: `vault_aws_secret_backend_role`](#resource-vault-aws-secret-backend-role)
- [Resource: `vault_database_secret_backend_role`](#resource-vault-database-secret-backend-role)
- [Resource: `vault_gcp_auth_backend_role`](#resource-gcp-auth-backend-role)
- [Resource: `vault_generic_secret`](#resource-vault-generic-secret)
- [Resource: `vault_pki_secret_backend_config_urls`](#resource-vault-pki-secret-backend-config-urls)
- [Resource: `vault_pki_secret_backend_role`](#resource-vault-pki-secret-backend-role)
- [Resource: `vault_pki_secret_backend_sign`](#resource-vault-pki-secret-backend-sign)
- [Resource: `vault_rabbitmq_secret_backend_role`](#resource-vault-rabbitmq-secret-backend-role)

<!-- /TOC -->

## Provider Version Configuration

-> Before upgrading to version `2.0.0`, it is recommended to upgrade to the most
recent version of the provider (`1.9.0`) and ensure that your environment
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

  version = "~> 1.9.0"
}
```

An updated configuration:

```hcl
provider "vault" {
  # ... other configuration ...

  version = "~> 2.0.0"
}
```

## Resource: `vault_auth_backend`

### Paths no longer have a trailing slash

In the `1.x` series of the Vault provider, the `vault_auth_backend` resource's `path` field and `id` both consistently have a trailing slash. To ensure what is stored in state matches what is written in your config, these fields will be stored in state with no trailing slash. Any interpolations involving these fields that relied on the trailing slash (for example, to manually rebuild a URL) should be updated to add a slash.

## Resource: `vault_aws_auth_backend_role`

### Deprecated fields have been removed

The following deprecated fields have been removed and will now throw an error if you try to use them:

- `bound_account_id` (use the `bound_accounts_ids` list instead)
- `bound_ami_id` (use the `bound_ami_ids` list instead)
- `bound_ec2_instance_id` (use the `bound_ec2_instance_ids` list instead)
- `bound_iam_instance_profile_arn` (use the `bound_iam_instance_profile_arns` list instead)
- `bound_iam_principal_arn` (use the `bound_iam_principal_arns` list instead)
- `bound_iam_role_arn` (use the `bound_iam_role_arns` list instead)
- `bound_region` (use the `bound_regions` list instead)
- `bound_subnet_id` (use the `bound_subnet_ids` list instead)
- `bound_vpc_id` (use the `bound_vpc_ids` list instead)

Specifying any of these fields in your config or trying to interpolate them in your config will raise an error. Use the list variations instead.

## Resource: `vault_database_secret_backend_role`

### Statements fields are now lists

The following fields have changed from strings to lists:

- `creation_statements`
- `renew_statements`
- `revocation_statements`
- `rollback_statements`

Anywhere they are specified in your config, they need to be turned into lists, by putting `[` and `]` around them. Anywhere they are interpolated, a list will now be returned. To get a string, use indexing or `for_each`.

## Resource: `vault_gcp_auth_backend_role`

### Deprecated fields have been removed

The following deprecated fields have been removed and will now throw an error if you try to use them:

- `project_id` (use the `bound_projects` list instead)

Specifying any of these fields in your config or trying to interpolate them in your config will raise an error. Use the list variations instead.

## Resource: `vault_generic_secret`

### Deprecated fields have been removed

The following deprecated fields have been removed and will now throw an error if you try to use them:

- `allow_read` (use the `disable_read` boolean instead)

Specifying any of these fields in your config or trying to interpolate them in your config will raise an error. Use the suggested fields instead.

## Resource: `vault_pki_secret_backend_config_urls`

### Fields are now lists

The following fields have changed from strings to lists:

- `crl_distribution_points`
- `issuing_certificates`
- `ocsp_servers`

Anywhere they are specified in your config, they need to be turned into lists, by putting `[` and `]` around them. Anywhere they are interpolated, a list will now be returned. To get a string, use indexing or `for_each`.

## Resource: `vault_pki_secret_backend_role`

### Certificate fields are now lists

The following fields have changed from strings to lists:

- `allowed_other_sans`
- `allowed_uri_sans`
- `country`
- `locality`
- `organization`
- `ou`
- `postal_code`
- `province`
- `street_address`

Anywhere they are specified in your config, they need to be turned into lists, by putting `[` and `]` around them. Anywhere they are interpolated, a list will now be returned. To get a string, use indexing or `for_each`.

## Resource: `vault_pki_secret_backend_sign`

### CA fields are now lists

The following fields have changed from strings to lists:

- `ca_chain`

Anywhere they are specified in your config, they need to be turned into lists, by putting `[` and `]` around them. Anywhere they are interpolated, a list will now be returned. To get a string, use indexing or `for_each`.

## Resource: `vault_rabbitmq_secret_backend_role`

### `vhost` is now a sub-block

The `vhosts` field is removed, and is now a `vhost` sub-block. Rather than storing the JSON formatted object in that string, it should now be expanded into the `host`, `configure`, and `read` fields on the `vhost` block. Any interpolations will need to be updated, and the configuration needs to be updated to match.

Example previous configuration:

```hcl
resource "vault_rabbitmq_secret_backend_role" "role" {
  backend = "${vault_rabbitmq_secret_backend.rabbitmq.path}"
  name    = "deploy"

  tags = "tag1,tag2"
  vhosts = "{\"/\": {\"configure\":\".*\", \"write\":\".*\", \"read\": \".*\"}}"
}
```

Example updated configuration:

```hcl
resource "vault_rabbitmq_secret_backend_role" "role" {
  backend = "${vault_rabbitmq_secret_backend.rabbitmq.path}"
  name    = "deploy"

  tags = "tag1,tag2"
  vhost {
    configure = ".*"
    host      = "/"
    read      = ".*"
    write     = ".*"
  }
}
```
