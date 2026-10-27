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

### Basic Example

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

### Example with Key Derivation and Context

```hcl
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "derived_key" {
  backend               = vault_mount.transit.path
  name                  = "derived_key"
  derived               = true
  convergent_encryption = true
  context               = "dGVzdGNvbnRleHQ="  # base64 encoded "testcontext"
  deletion_allowed      = true
}
```

### Example with Managed Key

```hcl
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "managed_key_by_name" {
  backend          = vault_mount.transit.path
  name             = "my_managed_key"
  type             = "managed_key"
  managed_key_name = "my_aws_kms_key"
  deletion_allowed = true
}

resource "vault_transit_secret_backend_key" "managed_key_by_id" {
  backend        = vault_mount.transit.path
  name           = "my_managed_key_by_id"
  type           = "managed_key"
  managed_key_id = "12345678-1234-1234-1234-123456789012"
  deletion_allowed = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Required) The path the transit secret backend is mounted at, with no leading or trailing `/`s.

* `name` - (Required) The name to identify this key within the backend. Must be unique within the backend.

* `type` - (Optional) Specifies the type of key to create. The currently-supported types are: `aes128-gcm96`, `aes256-gcm96` (default), `chacha20-poly1305`, `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `hmac`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `managed_key`, `aes128-cmac`, `aes192-cmac`, `aes256-cmac`, `ml-dsa`, `hybrid`, `slh-dsa`, `aes128-cbc`, and `aes256-cbc`.
    * Refer to the Vault documentation on transit key types for more information: [Key Types](https://www.vaultproject.io/docs/secrets/transit#key-types)
    * On Vault Enterprise 2.2.0+, changing `type` on an existing key rotates the key to a new key version
      using the new algorithm instead of replacing the key (see [crypto agility](#crypto-agility)).
      On any other Vault version, changing `type` forces a new resource.

* `deletion_allowed` - (Optional) Specifies if the keyring is allowed to be deleted. Must be set to 'true' before terraform will be able to destroy keys.

* `derived` - (Optional) Specifies if key derivation is to be used. If enabled, all encrypt/decrypt requests to this key must provide a context which is used for key derivation.

* `convergent_encryption` - (Optional) Whether or not to support convergent encryption, where the same plaintext creates the same ciphertext. This requires `derived` to be set to `true`.

* `exportable` - (Optional) Enables keys to be exportable. This allows for all valid private keys in the keyring to be exported. Once set, this cannot be disabled.

* `allow_plaintext_backup` - (Optional) Enables taking backup of entire keyring in the plaintext format. Once set, this cannot be disabled.
    * Refer to Vault API documentation on key backups for more information: [Backup Key](https://www.vaultproject.io/api-docs/secret/transit#backup-key)

* `min_decryption_version` - (Optional) Minimum key version to use for decryption.

* `min_encryption_version` - (Optional) Minimum key version to use for encryption

* `auto_rotate_period` - (Optional) Amount of seconds the key should live before being automatically rotated.
  A value of 0 disables automatic rotation for the key.

* `key_size` - (Optional) The key size in bytes for algorithms that allow variable key sizes. Currently only applicable to HMAC, where it must be between 32 and 512 bytes.

* `parameter_set` - (Optional) The parameter set to use for ML-DSA or SLH-DSA. Required for
  ML-DSA, hybrid, and SLH-DSA keys.
  Valid values for ML-DSA are `44`, `65`, and `87`.
Valid values for SLH-DSA are `slh-dsa-sha2-128s`, `slh-dsa-shake-128s`, `slh-dsa-sha2-128f`, `slh-dsa-shake-128`, `slh-dsa-sha2-192s`,
`slh-dsa-shake-192s`, `slh-dsa-sha2-192f`, `slh-dsa-shake-192f`, `slh-dsa-sha2-256s`, `slh-dsa-shake-256s`,
`slh-dsa-sha2-256f`, and `slh-dsa-shake-256f`.

* `hybrid_key_type_pqc` - (Optional) The post-quantum algorithm to use for hybrid signatures.
  Currently, ML-DSA is the only supported key type.

* `hybrid_key_type_ec` - (Optional) The elliptic curve algorithm to use for hybrid signatures.
  Supported key types are `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, and `ed25519`.

* `context` - (Optional) Base64 encoded context for key derivation. Required if `derived` is set to `true`. This provides additional entropy for key derivation and should be consistent across operations that need to use the same derived key.

* `managed_key_name` - (Optional) The name of the managed key to use when the key `type` is `managed_key`. This references a previously configured managed key in Vault (e.g., AWS KMS, Azure Key Vault, PKCS#11, etc.). When `type` is `managed_key`, either `managed_key_name` or `managed_key_id` must be specified. Changing this on an existing key forces a new resource unless the server supports [crypto agility](#crypto-agility).

* `managed_key_id` - (Optional) The UUID of the managed key to use when the key `type` is `managed_key`. This is the unique identifier of a previously configured managed key. When `type` is `managed_key`, either `managed_key_name` or `managed_key_id` must be specified. Changing this on an existing key forces a new resource unless the server supports [crypto agility](#crypto-agility).

## Crypto Agility

Vault Enterprise 2.2.0 added support for changing the algorithm when creating a new key version, so that a
single Transit key can contain key material for multiple key types. When the provider detects Vault Enterprise
2.2.0 or later, a change to `type`, `managed_key_name` or `managed_key_id` on an existing key is applied by
rotating the key through the `/transit/keys/:name/algorithm` endpoint. The new key type must have the same
`key_usages` as the existing key type, and any key type may be rotated to a `managed_key`. `parameter_set`,
`hybrid_key_type_pqc`, `hybrid_key_type_ec` and `key_size` are sent with the rotation when set, and must
be set as required by the new key type.

| `key_usages`             | Key Types                                                                                                              |
|--------------------------|------------------------------------------------------------------------------------------------------------------------|
| `aead-encryption`        | `aes128-gcm96`, `aes256-gcm96`, `chacha20-poly1305`                                                                    |
| `symmetric-encryption`   | `aes128-cbc`, `aes256-cbc`                                                                                             |
| `digital-signature`      | `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ed25519`, `ml-dsa`, `slh-dsa`, `hybrid`, `rsa-2048`, `rsa-3072`, `rsa-4096` |
| `asymmetric-encryption`  | `rsa-2048`, `rsa-3072`, `rsa-4096`                                                                                     |
| `message-authentication` | `hmac`, `aes128-cmac`, `aes192-cmac`, `aes256-cmac`                                                                    |

### Example: migrating a signing key to ML-DSA

```hcl
resource "vault_transit_secret_backend_key" "signing" {
  backend       = vault_mount.transit.path
  name          = "signing_key"
  type          = "ml-dsa"   # previously "ecdsa-p256"
  parameter_set = "65"
}
```

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

* `key_usages` - The usages of the key, derived from the key type. Only set on Vault Enterprise 2.2.0+.

## Import

Transit secret backend keys can be imported using the `path`, e.g.

```
$ terraform import vault_transit_secret_backend_key.key transit/keys/my_key
```
