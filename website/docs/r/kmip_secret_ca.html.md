---
layout: "vault"
page_title: "Vault: vault_kmip_secret_ca resource"
sidebar_current: "docs-vault-resource-kmip-secret-ca"
description: |-
  Manage KMIP Secret CAs in Vault.
---

# vault\_kmip\_secret\_ca

Manages KMIP Secret CAs in a Vault server. This feature requires
Vault Enterprise. See the [Vault documentation](https://www.vaultproject.io/docs/secrets/kmip)
for more information.

This resource supports both generating new CAs and importing existing ones.

## Example Usage

### Generate a New CA

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca" "generated" {
  path     = vault_kmip_secret_backend.default.path
  name     = "my-ca"
  key_type = "ec"
  key_bits = 256
  ttl      = 31536000 # 1 year in seconds
}
```

### Import an Existing CA

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca" "imported" {
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

resource "vault_kmip_secret_ca" "imported_with_fields" {
  path        = vault_kmip_secret_backend.default.path
  name        = "imported-ca-fields"
  ca_pem      = file("path/to/ca-certificate.pem")
  scope_field = "O"  # Use Organization field for scope
  role_field  = "OU" # Use Organizational Unit field for role
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) Path where KMIP backend is mounted. Must not begin or end with a `/`.

* `name` - (Required) Name to identify the CA. This will be used in the CA's path.

### For Generated CAs

* `key_type` - (Optional) CA key type (`rsa` or `ec`). Required for generated CAs. Conflicts with `ca_pem`.

* `key_bits` - (Optional) CA key bits. Valid values depend on `key_type`:
  - For `rsa`: 2048, 3072, 4096
  - For `ec`: 224, 256, 384, 521
  
  Required for generated CAs. Conflicts with `ca_pem`.

* `ttl` - (Optional) CA TTL in seconds. Defaults to 365 days (31536000 seconds). Only used for generated CAs. Conflicts with `ca_pem`.

### For Imported CAs

* `ca_pem` - (Optional) CA certificate in PEM format. Required for imported CAs. Conflicts with `key_type`, `key_bits`, and `ttl`.

* `scope_name` - (Optional) The scope name to associate with this CA. For imported CAs, must specify either `scope_name` or `scope_field`.

* `scope_field` - (Optional) The field in the certificate to use for the scope. Valid values are `CN`, `O`, `OU`, or `UID`. For imported CAs, must specify either `scope_name` or `scope_field`.

* `role_name` - (Optional) The role name to associate with this CA. For imported CAs, must specify either `role_name` or `role_field`.

* `role_field` - (Optional) The field in the certificate to use for the role. Valid values are `CN`, `O`, `OU`, or `UID`. For imported CAs, must specify either `role_name` or `role_field`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The ID of the CA in the format `<path>/ca/<name>`.

* `key_type` - The key type of the CA (only for generated CAs).

* `key_bits` - The key bits of the CA (only for generated CAs).

## Import

KMIP Secret CA can be imported using the format `<path>/ca/<name>`, e.g.

```
$ terraform import vault_kmip_secret_ca.example kmip/ca/my-ca
```

## Notes

* When generating a CA, the `key_type` and `key_bits` parameters are required.
* When importing a CA, the `ca_pem` parameter is required, along with either:
  - Both `scope_name` and `role_name`, or
  - Both `scope_field` and `role_field`, or
  - A combination of name and field parameters
* The `scope_name`, `scope_field`, `role_name`, and `role_field` parameters can be updated for imported CAs.
* All other parameters require replacement if changed.