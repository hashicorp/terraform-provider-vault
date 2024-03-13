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
to upgrade from version `3.25.0` to `4.0.0`.

Most of the changes outlined in this guide have been previously marked as
deprecated in the Terraform `plan`/`apply` output throughout previous provider
releases, up to and including 3.25.0. These changes, such as deprecation notices,
can always be found in the [CHANGELOG](https://github.com/hashicorp/terraform-provider-vault/blob/master/CHANGELOG.md).

-> If you are upgrading from `1.9.x`. Please follow the
[2.0.0 Upgrade Guide](./version_2_upgrade.html) before proceeding any further.

-> If you are upgrading from `2.24.x`. Please follow the
[3.0.0 Upgrade Guide](./version_3_upgrade.html) before proceeding any further.

## Why version 4.0.0?

We introduced version `4.0.0` of the Vault provider in order to make
performance improvements for deployments that manage many Vault secret or auth
engine mounts. This improvement required changes to the underlying Vault API
calls, which in turn would require policy adjustments in environments where
permissions are least privilege.

The change was deemed significant enough to warrant the major version bump.
In addition to the aforementioned performance improvements, all previously deprecated fields
and resources have been removed.

While you may see some small changes in your configurations as a result of
these changes, we don't expect you'll need to make any major refactorings.
However, please pay special attention to the changes noted in the [Provider Policy Changes](#provider-policy-changes) section.

## What performance improvements should we expect to see?

Version `4.0.0` changed the READ operations across many resources to call Vault
API's to only fetch mount metadata necessary for the resource.  Previously,
these resources were calling a Vault API which returned mount metadata for all
enabled mounts. This would result in a substantially higher CPU and memory
footprint for the provider in cases where a given Vault server has a large
number of secret/auth mounts.

The following is the list of resources that should see performance improvements
when many mounts are enabled in Vault:

#### Data sources
- `vault_auth_backend`

#### Resources
- `vault_auth_backend`
- `vault_aws_secret_backend`
- `vault_azure_secret_backend`
- `vault_consul_secret_backend`
- `vault_gcp_auth_backend`
- `vault_gcp_secret_backend`
- `vault_github_auth_backend`
- `vault_jwt_auth_backend`
- `vault_ldap_auth_backend`
- `vault_mount`
- `vault_okta_auth_backend`
- `vault_pki_secret_backend_cert`
- `vault_rabbitmq_secret_backend`
- `vault_terraform_cloud_secret_backend`

## What Vault server versions are supported in version 4.X?

The Vault provider will be dropping Vault version support for Vault <= v1.10.0.
This means that only Vault server version 1.11.x and greater will be supported.

## What is the impact of these changes?

With this change, Vault will require read policies to be set at the path level.
For example, instead of permissions at `sys/auth` you must set permissions at
the `sys/auth/:path` level. Please refer to the details in the
[Provider Policy Changes](#provider-policy-changes) section.

The changes in this case are blocking but not destructive. That is, deployments
will fail until the required Vault policy adjustments have been made.

## Which Terraform versions are supported?

Terraform versions `1.0.x ` and greater are fully supported.

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
- [Provider Policy Changes](#provider-policy-changes)
  - [Auth method resource changes](#auth-method-resource-changes)
  - [Secret engine resource changes](#secret-engine-resource-changes)
- [Deprecated Field Removals](#deprecated-field-removals)
  - [AD Secret Backend](#ad-secret-backend)
    - [`length`](#ad-secret-backend)
    - [`formatter`](#ad-secret-backend)
  - [Cert Auth Backend: `allowed_organization_units`](#cert-auth-backend-role)
  - [Consul Backend Role: `token_type`](#console-backend-role)
  - [Identity Group Member Entities: `group_name`](#identity-group-member-entities)
  - [LDAP Secret Backend: `length`](#ldap-secret-backend)
  - [PKI Root Cert: `serial`](#pki-root-cert)
  - [PKI Root Sign Intermediate: `serial`](#pki-root-sign-intermediate)
  - [PKI Root Sign: `serial`](#pki-sign)
  - [SSH Backend Role: `allowed_user_key_lengths`](#ssh-backend-role)
  - [Transit Secret Backend Key: `auto_rotate_interval`](#transit-secret-backend-key)

<!-- /TOC -->

## Provider Version Configuration

-> Before upgrading to version `4.0.0`, it is recommended to upgrade to the most
recent version of the provider (`3.25.0`) and ensure that your environment
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

  version = "~> 3.25.0"
}
```

An updated configuration:

```hcl
provider "vault" {
  # ... other configuration ...

  version = "~> 4.0.0"
}
```

## Provider Policy Changes

Version `4.0.0` of the Vault provider made changes to the underlying Vault API
calls, which in turn may require policy adjustments in environments where
permissions are least privilege.

Please see the [Capabilities](https://developer.hashicorp.com/vault/docs/concepts/policies#capabilities)
section of the Vault Policies documentation for more information on Vault
policies.

### Auth method resource changes

The below table specifies what changed between version 3.X and 4.X for the
following resources:

#### Data sources
- `vault_auth_backend`

#### Resources
- `vault_auth_backend`
- `vault_gcp_auth_backend`
- `vault_github_auth_backend`
- `vault_jwt_auth_backend`
- `vault_ldap_auth_backend`
- `vault_okta_auth_backend`

-> Note that the table below does not include any additional policies the
individual resources might require.

<table>
<thead>
  <tr>
    <th colspan="2">3.X</th>
    <th colspan="2">4.X</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Method</td>
    <td>Path</td>
    <td>Method</td>
    <td>Path</td>
  </tr>
  <tr>
    <td>GET</td>
    <td>sys/auth</td>
    <td>GET</td>
    <td>sys/auth/:path</td>
  </tr>
</tbody>
</table>

For example, in version 3.X the `vault_gcp_auth_backend` resource retrieves
mount metadata with the GET `sys/auth` HTTP operation which corresponds to the
following policy in Vault:

```hcl
path "sys/auth"
{
    capabilities = ["read"]
}
```

In version 4.X the `vault_gcp_auth_backend` resource retrieves mount metadata
with the GET `sys/auth/:path` HTTP operation which corresponds to the following
policy in Vault:

```hcl
path "sys/auth/gcp"
{
    capabilities = ["read"]
}
```

### Secret engine resource changes

The below table specifies what changed between version 3.X and 4.X for the
following resources:

#### Resources
  - `vault_aws_secret_backend`
  - `vault_azure_secret_backend`
  - `vault_consul_secret_backend`
  - `vault_gcp_secret_backend`
  - `vault_mount`
  - `vault_pki_secret_backend_cert`
  - `vault_rabbitmq_secret_backend`
  - `vault_terraform_cloud_secret_backend`

-> Note that the table below does not include any additional policies the
individual resources might require.

<table>
<thead>
  <tr>
    <th colspan="2">3.X</th>
    <th colspan="2">4.X</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Method</td>
    <td>Path</td>
    <td>Method</td>
    <td>Path</td>
  </tr>
  <tr>
    <td>GET</td>
    <td>sys/mounts</td>
    <td>GET</td>
    <td>sys/mounts/:path</td>
  </tr>
</tbody>
</table>

For example, in version 3.X the `vault_gcp_secret_backend` resource retrieves
mount metadata with the GET `sys/mounts` HTTP operation which corresponds to the
following policy in Vault:

```hcl
path "sys/mounts"
{
    capabilities = ["read"]
}
```

In version 4.X the `vault_gcp_secret_backend` resource retrieves mount metadata
with the GET `sys/mounts/:path` HTTP operation which corresponds to the following
policy in Vault:

```hcl
path "sys/mounts/gcp"
{
  capabilities = ["read"]
}
```

The below table specifies what changed between version 3.X and 4.X for the
following resources:

#### Resources
  - `vault_ad_secret_backend`
  - `vault_nomad_secret_backend`

-> Note that the table below does not include any additional policies the
individual resources might require.

<table>
<thead>
  <tr>
    <th colspan="2">3.X</th>
    <th colspan="2">4.X</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Method</td>
    <td>Path</td>
    <td>Method</td>
    <td>Path</td>
  </tr>
  <tr>
    <td>GET</td>
    <td>sys/mounts/:path/tune</td>
    <td>GET</td>
    <td>sys/mounts/:path</td>
  </tr>
</tbody>
</table>

For example, in version 3.X the `vault_nomad_secret_backend` resource retrieves
mount tune metadata with the GET `sys/mounts/:path/tune` HTTP operation which
corresponds to the following policy in Vault:

```hcl
path "sys/mounts/nomad/tune"
{
    capabilities = ["read"]
}
```

In version 4.X the `vault_nomad_secret_backend` resource retrieves mount metadata
with the GET `sys/mounts/:path` HTTP operation which corresponds to the following
policy in Vault:

```hcl
path "sys/mounts/nomad"
{
  capabilities = ["read"]
}
```

## Deprecated Field Removals

The following deprecated fields have been removed:

### AD Secret Backend

* `length` - removed from the `vault_ad_secret_backend` resource.

* `formatter` - removed from the `vault_ad_secret_backend` resource.

### Cert Auth Backend Role

* `allowed_organization_units` - removed from the `vault_cert_auth_backend_role` resource.

### Consul Backend Role

* `token_type` - removed from the `vault_consul_secret_backend_role` resource.

### Identity Group Member Entities

* `group_name` - removed from the `vault_identity_group_member_entity_ids` resource.

### LDAP Secret Backend

* `length` - removed from the `vault_ldap_secret_backend` resource.

### PKI Root Cert

* `serial` - removed from the `vault_pki_secret_backend_root_cert` resource. Use `serial_number` instead.

### PKI Root Sign Intermediate

* `serial` - removed from the `vault_pki_secret_backend_root_sign_intermediate` resource. Use `serial_number` instead.

### PKI Root Sign

* `serial` - removed from the `vault_pki_secret_backend_sign` resource. Use `serial_number` instead.

### SSH Backend Role

* `allowed_user_key_lengths` - removed from the `vault_ssh_secret_backend_role`
  resource. Use `allowed_user_key_config` instead.

### Transit Secret Backend Key

* `auto_rotate_interval` - removed from the `vault_transit_secret_backend_key`
  resource. Use `auto_rotate_period` instead.
