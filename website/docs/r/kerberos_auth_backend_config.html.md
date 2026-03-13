---
layout: "vault"
page_title: "Vault: vault_kerberos_auth_backend_config resource"
sidebar_current: "docs-vault-resource-kerberos-auth-backend-config"
description: |-
  Manages the configuration of a Kerberos Auth Backend in Vault.
---

# vault\_kerberos\_auth\_backend\_config

Manages the configuration of a Kerberos Auth Backend in Vault.

This resource configures the Kerberos authentication method by providing the keytab
and service account information required for Vault to authenticate users via Kerberos.

For more information, see the
[Vault docs](https://www.vaultproject.io/docs/auth/kerberos).

~> **Important** The `keytab_wo` field is write-only and is not stored in Terraform state.
It is only sent to Vault during configuration. See [the main provider documentation](../index.html)
for more details.

~> **Note** Vault does not support deleting auth backend configurations via the API.
When this resource is destroyed or replaced (e.g., when changing the `path`), it is 
only removed from Terraform state. The configuration remains in Vault until the auth 
mount itself is deleted.

## Example Usage

### Basic Configuration

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount           = vault_auth_backend.kerberos.path
  keytab_wo       = filebase64("/path/to/vault.keytab")
  service_account = "vault/localhost@EXAMPLE.COM"
}
```

### Full Configuration with All Options

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount                = vault_auth_backend.kerberos.path
  keytab_wo            = filebase64("/path/to/vault.keytab")
  service_account      = "vault/localhost@EXAMPLE.COM"
  remove_instance_name = true
  add_group_aliases    = true
}
```

### Using Namespace (Vault Enterprise)

```hcl
resource "vault_namespace" "example" {
  path = "example-namespace"
}

resource "vault_auth_backend" "kerberos" {
  namespace = vault_namespace.example.path
  type      = "kerberos"
  path      = "kerberos"
}

resource "vault_kerberos_auth_backend_config" "config" {
  namespace       = vault_namespace.example.path
  mount           = vault_auth_backend.kerberos.path
  keytab_wo       = filebase64("/path/to/vault.keytab")
  service_account = "vault/localhost@EXAMPLE.COM"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where the Kerberos auth method is mounted.
  Changing this will force a new resource to be created.

* `keytab_wo` - (Required) Base64-encoded keytab file content. This is a write-only
  field and is not stored in Terraform state. The keytab must contain an entry
  matching the `service_account`.

* `service_account` - (Required) The Kerberos service account associated with the 
  keytab entry (e.g., `vault/localhost@EXAMPLE.COM` or `vault_svc`).

* `remove_instance_name` - (Optional) Removes instance names from Kerberos service 
  principal names during authentication. This can be useful when the instance name 
  is not relevant for authentication. Defaults to `false`.

* `add_group_aliases` - (Optional) Adds group aliases during authentication. When 
  enabled, Vault will create entity aliases for each group the user belongs to. 
  Defaults to `false`.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Kerberos auth backend configurations can be imported using the `path`, e.g.

```
$ terraform import vault_kerberos_auth_backend_config.config auth/kerberos/config
```

~> **Note** The `keytab_wo` field cannot be imported as it is write-only and not stored
in state. You will need to provide it in your configuration after import.

### Importing with Namespace (Vault Enterprise)

For Vault Enterprise with namespaces, set the `TERRAFORM_VAULT_NAMESPACE_IMPORT` environment variable 
before importing:

```
$ export TERRAFORM_VAULT_NAMESPACE_IMPORT=example-namespace
$ terraform import vault_kerberos_auth_backend_config.config auth/kerberos/config