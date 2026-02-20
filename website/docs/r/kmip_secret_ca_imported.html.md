---
layout: "vault"
page_title: "Vault: vault_kmip_secret_ca_imported resource"
sidebar_current: "docs-vault-resource-kmip-secret-ca-imported"
description: |-
  Manage imported KMIP Secret CAs in Vault.
---

# vault\_kmip\_secret\_ca\_imported

Manages imported KMIP Secret CAs in a Vault server. This resource imports an existing CA certificate. This feature requires Vault Enterprise. See the [Vault documentation](https://www.vaultproject.io/docs/secrets/kmip) for more information.

## Example Usage

### Import CA with Named Scope and Role

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca_imported" "named" {
  path       = vault_kmip_secret_backend.default.path
  name       = "imported-ca"
  ca_pem     = file("path/to/ca-certificate.pem")
  scope_name = "production"
  role_name  = "admin"
}
```

### Import CA with Field-Based Mapping

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca_imported" "field_based" {
  path        = vault_kmip_secret_backend.default.path
  name        = "imported-ca-fields"
  ca_pem      = file("path/to/ca-certificate.pem")
  scope_field = "O"  # Use Organization field for scope
  role_field  = "OU" # Use Organizational Unit field for role
}
```

### Import CA with Mixed Mapping

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca_imported" "mixed" {
  path        = vault_kmip_secret_backend.default.path
  name        = "imported-ca-mixed"
  ca_pem      = file("path/to/ca-certificate.pem")
  scope_name  = "production"
  role_field  = "CN" # Use Common Name field for role
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).

* `path` - (Required) Path where KMIP backend is mounted. Must not begin or end with a `/`.

* `name` - (Required) Name to identify the CA. This will be used in the CA's path.

* `ca_pem` - (Required) CA certificate in PEM format.

* `scope_name` - (Optional) The scope name to associate with this CA. Must specify exactly one of `scope_name` or `scope_field`.

* `scope_field` - (Optional) The field in the certificate to use for the scope. Valid values are `CN`, `O`, `OU`, or `UID`. Must specify exactly one of `scope_name` or `scope_field`.

* `role_name` - (Optional) The role name to associate with this CA. Must specify exactly one of `role_name` or `role_field`.

* `role_field` - (Optional) The field in the certificate to use for the role. Valid values are `CN`, `O`, `OU`, or `UID`. Must specify exactly one of `role_name` or `role_field`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The ID of the CA in the format `<path>/ca/<name>`.

## Import

KMIP Secret CA Imported can be imported using the format `<path>/ca/<name>`, e.g.

```
$ terraform import vault_kmip_secret_ca_imported.example kmip/ca/my-ca
```

**Note:** When importing, the `ca_pem` value cannot be retrieved from Vault and will need to be set in your configuration. This value will be ignored during import verification.

## Configuration Requirements

When configuring an imported CA, you must specify:

* Exactly one of `scope_name` or `scope_field`
* Exactly one of `role_name` or `role_field`

You can mix and match name-based and field-based configurations. For example, you can use `scope_name` with `role_field`.

## Updating

The `scope_name`, `scope_field`, `role_name`, and `role_field` parameters can be updated after creation. All other parameters require replacement if changed.