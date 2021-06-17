---
layout: "vault"
page_title: "Vault: vault_transit_secret_backend_key resource"
sidebar_current: "docs-vault-resource-transit-secret-backend-key"
description: |-
  Create an Encryption Keyring on a Transit Secret Backend for Vault.
---

# vault\_transit\_secret\_backend\_key

Creates an Encryption Keyring on a Transit Secret Backend for Vault.

## Example Usage

```hcl
resource "vault_mount" "transit" {
  path                      = "transit"
  type                      = "transit"
  description               = "Example description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_transit_secret_backend_key" "key" {
  backend = vault_mount.transit.path
  name    = "my_key"
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) The path the transit secret backend is mounted at, with no leading or trailing `/`s.

* `name` - (Required) The name to identify this key within the backend. Must be unique within the backend.

* `type` - (Optional) Specifies the type of key to create. The currently-supported types are: `aes128-gcm96`, `aes256-gcm96` (default), `chacha20-poly1305`, `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-2048`, `rsa-3072` and `rsa-4096`. 
    * Refer to the Vault documentation on transit key types for more information: [Key Types](https://www.vaultproject.io/docs/secrets/transit#key-types)

* `deletion_allowed` - (Optional) Specifies if the keyring is allowed to be deleted. Must be set to 'true' before terraform will be able to destroy keys.

* `derived` - (Optional) Specifies if key derivation is to be used. If enabled, all encrypt/decrypt requests to this key must provide a context which is used for key derivation.

* `convergent_encryption` - (Optional) Whether or not to support convergent encryption, where the same plaintext creates the same ciphertext. This requires `derived` to be set to `true`.

* `exportable` - (Optional) Enables keys to be exportable. This allows for all valid private keys in the keyring to be exported. Once set, this cannot be disabled.

* `allow_plaintext_backup` - (Optional) Enables taking backup of entire keyring in the plaintext format. Once set, this cannot be disabled.
    * Refer to Vault API documentation on key backups for more information: [Backup Key](https://www.vaultproject.io/api-docs/secret/transit#backup-key)
    
* `min_decryption_version` - (Optional) Minimum key version to use for decryption.

* `min_encryption_version` - (Optional) Minimum key version to use for encryption

## Attributes Reference

* `keys` - List of key versions in the keyring. This attribute is zero-indexed and will contain a map of values depending on the `type` of the encryption key.
    * for key types `aes128-gcm96`, `aes256-gcm96` and `chacha20-poly1305`, each key version will be a map of a single value `id` which is just a hash of the key's metadata.
    * for key types `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-2048`, `rsa-3072` and `rsa-4096`, each key version will be a map of the following:
        * `name` - Name of keychain
        * `creation_time` - ISO 8601 format timestamp indicating when the key version was created
        * `public_key` - This is the base64-encoded public key for use outside of Vault.
        
* `latest_version` - Latest key version available. This value is 1-indexed, so if `latest_version` is `1`, then the key's information can be referenced from `keys` by selecting element `0`

* `min_available_version` - Minimum key version available for use. If keys have been archived by increasing `min_decryption_version`, this attribute will reflect that change.

* `supports_encryption` - Whether or not the key supports encryption, based on key type.

* `supports_decryption` - Whether or not the key supports decryption, based on key type.

* `supports_derivation` - Whether or not the key supports derivation, based on key type.

* `supports_signing` - Whether or not the key supports signing, based on key type.



## Import

Transit secret backend keys can be imported using the `path`, e.g.

```
$ terraform import vault_transit_secret_backend_key.key transit/keys/my_key
```
