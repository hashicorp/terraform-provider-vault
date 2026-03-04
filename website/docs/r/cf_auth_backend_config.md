---
layout: "vault"
page_title: "Vault: vault_cf_auth_backend_config resource"
sidebar_current: "docs-vault-resource-cf-auth-backend-config"
description: |-
  Manages the configuration for the CloudFoundry auth backend in Vault.
---

# vault\_cf\_auth\_backend\_config

Manages the configuration for the [CloudFoundry (CF) auth method](https://developer.hashicorp.com/vault/docs/auth/cf) in Vault.

~> **Important** The `cf_password_wo` field is write-only and will never be
stored in Terraform state. See [Ephemeral Attributes Reference](#ephemeral-attributes-reference) below.

## Example Usage

```hcl
resource "vault_auth_backend" "cf" {
  type = "cf"
  path = "cf"
}

resource "vault_cf_auth_backend_config" "config" {
  mount                        = vault_auth_backend.cf.path
  identity_ca_certificates     = [trimspace(file("ca.pem"))]
  cf_api_addr                  = "https://api.my-cf.example.com"
  cf_username                  = "admin"
  cf_password_wo               = var.cf_password
  login_max_seconds_not_before = 300
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) The mount path for the CF auth engine in Vault.

* `identity_ca_certificates` - (Required) A set of root CA PEM certificates used
  to verify that `CF_INSTANCE_CERT` presented at login was issued by the proper
  authority.

* `cf_api_addr` - (Required) The full API address of the CF deployment, used to
  verify that a given `CF_INSTANCE_CERT` references an application, space, and
  organization that currently exist.

* `cf_username` - (Required) The username for authenticating to the CF API.

* `cf_api_trusted_certificates` - (Optional) A set of PEM-encoded certificates
  presented by the CF API. Configures Vault to trust these certificates when
  making API calls.

* `login_max_seconds_not_before` - (Optional, Computed) The maximum number of
  seconds in the past when a login signature could have been created. Defaults
  to `300`. Because this field is `Computed`, removing it from your configuration
  does **not** reset the value in Vault — Vault retains whatever was previously
  set. To reset to the default, set the field explicitly to `300`.

* `login_max_seconds_not_after` - (Optional, Computed) The maximum number of
  seconds in the future when a login signature could have been created. Defaults
  to `60`. Because this field is `Computed`, removing it from your configuration
  does **not** reset the value in Vault — Vault retains whatever was previously
  set. To reset to the default, set the field explicitly to `60`.

* `cf_timeout` - (Optional) The timeout for CF API calls in seconds. Defaults to
  `0` (no timeout). Removing this field from your configuration resets the value
  to `0` in Vault.

## Ephemeral Attributes Reference

The following write-only attribute is supported:

* `cf_password_wo` - (Required) The password for authenticating to the CF API,
  provided as a write-only field. This value will **never** be stored in
  Terraform state or plan files.

## Import

CF auth backend configs can be imported using `auth/`, the `mount` path, and
`/config`, e.g.

```
$ terraform import vault_cf_auth_backend_config.config auth/cf/config
```

The namespace can be set using the environment variable `TERRAFORM_VAULT_NAMESPACE`.
