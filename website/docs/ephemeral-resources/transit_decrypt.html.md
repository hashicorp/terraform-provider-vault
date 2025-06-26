---
layout: "vault"
page_title: "Vault: ephemeral vault_transit_decrypt resource"
sidebar_current: "docs-vault-ephemeral-transit-decrypt"
description: |-
  Decrypt ciphertext using a Vault Transit encryption key.
---

# vault_transit_decrypt

This is a data source which can be used to decrypt ciphertext using a Vault Transit key.

Decrypts an ephemeral cyphertext from the Vault Transit engine that is not stored in the remote TF state.
For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/docs/secrets/transit)
for the Transit engine.

## Example Usage

```hcl
resource "vault_mount" "transit" {
    path = "transit"
    type = "transit"
}

resource "vault_transit_secret_backend_key" "my-key" {
    name             = "my-key"
    backend          = vault_mount.transit.path
    deletion_allowed = true
}

data "vault_transit_encrypt" "encrypted" {
    backend   = vault_mount.transit.path
    key       = vault_transit_secret_backend_key.my-key.name
    plaintext = "foo"
}

ephemeral "vault_transit_decrypt" "decrypted" {
    backend    = vault_mount.transit.path
    key        = vault_transit_secret_backend_key.my-key.name
    ciphertext = data.vault_transit_encrypt.encrypted.ciphertext
}
```

## Argument Reference

Each document configuration may have one or more `rule` blocks, which each accept the following arguments:

- `key` - (Required) Specifies the name of the transit key to decrypt against.

- `backend` - (Required) The path the transit secret backend is mounted at, with no leading or trailing `/`.

- `ciphertext` - (Required) Ciphertext to be decoded.

- `context` - (Optional) Context for key derivation. This is required if key derivation is enabled for this key.

## Attributes Reference

- `plaintext` - Decrypted plaintext returned from Vault
