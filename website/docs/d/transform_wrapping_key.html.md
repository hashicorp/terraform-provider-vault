---
layout: "vault"
page_title: "Vault: vault_transform_wrapping_key data source"
sidebar_current: "docs-vault-datasource-transform-wrapping-key"
description: |-
  Reads the public wrapping key of a Transform secrets engine mount.
---

# vault\_transform\_wrapping\_key

Reads the public wrapping key of a Transform secrets engine mount. Use it to wrap key material
before importing it (BYOK).

~> **Vault Enterprise only** The Transform secrets engine requires Vault Enterprise.

For more information, please refer to [the Vault Transform documentation](https://developer.hashicorp.com/vault/api-docs/secret/transform).

## Example Usage

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}

data "vault_transform_wrapping_key" "wrapping_key" {
  mount = vault_mount.transform.path
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).s

* `mount` - (Required) Path where the Transform secrets engine is mounted.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `public_key` - The PEM-encoded 4096-bit RSA public wrapping key.
