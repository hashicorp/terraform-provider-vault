---
layout: "vault"
page_title: "Vault: vault_secret_backend_wrapping_key data source"
sidebar_current: "docs-vault-datasource-secret-backend-wrapping-key"
description: |-
  Reads the public wrapping key of a secrets engine mount.
---

# vault\_secret\_backend\_wrapping\_key

Reads the public wrapping key of a secrets engine mount. Use it to wrap key material
before importing it (BYOK). Currently supported by the Transit and Transform secrets engines.

For more information, please refer to [the Vault Transit documentation](https://developer.hashicorp.com/vault/api-docs/secret/transit#get-wrapping-key).

## Example Usage

```hcl
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

data "vault_secret_backend_wrapping_key" "wrapping_key" {
  mount = vault_mount.transit.path
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where the secrets engine is mounted.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `public_key` - The PEM-encoded 4096-bit RSA public wrapping key.
