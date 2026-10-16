---
layout: "vault"
page_title: "Vault: vault_transit_secret_backend_key_import resource"
sidebar_current: "docs-vault-resource-transit-secret-backend-key-import"
description: |-
  Imports existing key material into a Transit secret backend for Vault and manages its ongoing configuration in place.
---

# vault\_transit\_secret\_backend\_key\_import

Imports existing key material (BYOK) or public keys into a new Transit encryption key and manages ongoing key configuration in place.

~> **Deletion and replacement** Vault requires `deletion_allowed` to be `true` before a key can be deleted. This applies both to `terraform destroy` and to any plan that replaces the resource (e.g. changing `type`, `ciphertext`, `allow_rotation`, or other immutable fields). Set `deletion_allowed = true` in your configuration before making changes that would trigger replacement.

For more information, please refer to [the Vault Transit documentation](https://developer.hashicorp.com/vault/api-docs/secret/transit#import-key).

## Example Usage

### Public Key Import

```hcl
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key_import" "example_pubkey" {
  mount      = vault_mount.transit.path
  name       = "my-public-key"
  type       = "ecdsa-p256"
  public_key = file("${path.module}/public.pem")
}
```

### Wrapped Private / Symmetric Key Import (BYOK)

Private and symmetric keys must be wrapped before import. See the [Transit key wrapping guide](https://developer.hashicorp.com/vault/docs/secrets/transit/key-wrapping-guide) for how to produce the wrapped payload.

```hcl
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

data "vault_secret_backend_wrapping_key" "wrapping_key" {
  mount = vault_mount.transit.path
}

# Construct ciphertext by wrapping key material with the public wrapping key using RSA-OAEP + AES-GCM
resource "vault_transit_secret_backend_key_import" "example_byok" {
  mount      = vault_mount.transit.path
  name       = "my-imported-key"
  type       = "aes256-gcm96"
  ciphertext = var.wrapped_ciphertext
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where the Transit secret backend is mounted. Changing this forces a new resource.

* `name` - (Required) Name of the encryption key to create. Changing this forces a new resource.

* `type` - (Required) Specifies the type of key to create. Supported types: `aes128-gcm96`, `aes256-gcm96`, `chacha20-poly1305`, `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `hmac`, `aes128-cmac`, `aes192-cmac`, `aes256-cmac`. Changing this forces a new resource.

* `ciphertext` - (Optional, Sensitive) A base64-encoded string containing the wrapped ephemeral AES key and the encrypted key material. Required when importing private or symmetric keys. Changing this forces a new resource.

* `public_key` - (Optional) A plaintext PEM public key to be imported for public-key-only import. Changing this forces a new resource.

* `hash_function` - (Optional) The hash function used for the RSA-OAEP step of creating the ciphertext (`SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`). Defaults to `SHA256`. Changing this forces a new resource.

* `allow_rotation` - (Optional) If set to `true`, the imported key can be rotated within Vault using the rotate endpoint. Changing this forces a new resource.

* `derived` - (Optional) Specifies if key derivation is to be used. Changing this forces a new resource.

* `context` - (Optional, Sensitive) A base64-encoded string providing a context for key derivation. Required if `derived` is true. Changing this forces a new resource.

* `deletion_allowed` - (Optional) Specifies if the key is allowed to be deleted. Must be set to `true` before the resource can be destroyed or replaced. Can be updated in place.

* `exportable` - (Optional) Enables keys to be exportable. Once set to `true`, this cannot be disabled. Can be updated in place.

* `allow_plaintext_backup` - (Optional) If set, enables taking backup of named key in plaintext format. Once set to `true`, this cannot be disabled. Can be updated in place.

* `auto_rotate_period` - (Optional) The period in seconds at which this key should be rotated automatically. Set to `0` to disable. Can be updated in place.

* `min_decryption_version` - (Optional) Minimum key version to use for decryption. Can be updated in place.

* `min_encryption_version` - (Optional) Minimum key version to use for encryption. Can be updated in place.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `min_available_version` - Minimum key version available for use.
* `imported_key` - Whether the key was imported into Vault (as opposed to generated by Vault).
* `imported_key_allow_rotation` - Whether the imported key is configured to allow rotation.
* `latest_version` - Latest key version in use in the keyring.
* `latest_version_type` - The key type of the latest key version in the keyring. *Available only for Vault 2.1 or later*.
* `supports_encryption` - Whether the key supports encryption.
* `supports_decryption` - Whether the key supports decryption.
* `supports_derivation` - Whether the key supports derivation.
* `supports_signing` - Whether the key supports signing.
* `keys` - List of key versions and metadata in the keyring.

## Import

Transit keys can be imported using the `{mount}/keys/{name}` or `{mount}/{name}` format:

```
$ terraform import vault_transit_secret_backend_key_import.example transit/keys/my-imported-key
```
