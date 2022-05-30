---
layout: "vault"
page_title: "Vault: vault_transit_encrypt data source"
sidebar_current: "docs-vault-datasource-transit-encrypt"
description: |-
  Encrypts plaintext using a Vault Transit encryption key.
---

# vault\_transit\_encrypt

This is a data source which can be used to encrypt plaintext using a Vault Transit key.

## Example Usage

```hcl
resource "vault_mount" "test" {
  path        = "transit"
  type        = "transit"
  description = "This is an example mount"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = "vault_mount.test.path
  name    = "test"
}

data "vault_transit_encrypt" "test" {
  backend   = vault_mount.test.path
  key       = vault_transit_secret_backend_key.test.name
  plaintext = "foobar"
}
```

## Argument Reference

Each document configuration may have one or more `rule` blocks, which each accept the following arguments:

* `key` - (Required) Specifies the name of the transit key to encrypt against.

* `backend` - (Required) The path the transit secret backend is mounted at, with no leading or trailing `/`.

* `plaintext` - (Required) Plaintext to be encoded.

* `context` - (Optional) Context for key derivation. This is required if key derivation is enabled for this key.

* `key_version` - (Optional) The version of the key to use for encryption. If not set, uses the latest version. Must be greater than or equal to the key's `min_encryption_version`, if set.

## Attributes Reference

* `ciphertext` - Encrypted ciphertext returned from Vault
