---
layout: "vault"
page_title: "Vault: vault_transit_secret_backend_imported_key resource"
sidebar_current: "docs-vault-resource-transit-secret-backend-imported-key"
description: |-
  Imports existing key material into a Transit secret backend for Vault and manages its ongoing configuration in place.
---

# vault\_transit\_secret\_backend\_imported\_key

Imports existing key material (BYOK) or public keys into a new Transit encryption key and manages ongoing key configuration in place.

~> **Deletion and replacement** Vault requires `deletion_allowed` to be `true` before a key can be deleted to protect from accidental deletion. This applies both to `terraform destroy` and to any plan that replaces the resource (see the arguments marked "Changing this forces a new resource"). Set `deletion_allowed = true` in your configuration before making changes that would trigger replacement.

~> **Importing new key versions** After the initial import, changing `public_key`, or changing `ciphertext_wo` together with `ciphertext_wo_version`, imports the new key material into the existing key through Vault's [import key version](https://developer.hashicorp.com/vault/api-docs/secret/transit#import-key-version) endpoint. This only works on keys that were imported into Vault and have not been rotated inside Vault. Vault validates the combination of arguments and returns an error for unsupported ones.

For more information, please refer to [the Vault Transit documentation](https://developer.hashicorp.com/vault/api-docs/secret/transit#import-key).

## Example Usage

### Public Key Import

```hcl
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_imported_key" "example_pubkey" {
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
resource "vault_transit_secret_backend_imported_key" "example_byok" {
  mount                 = vault_mount.transit.path
  name                  = "my-imported-key"
  type                  = "aes256-gcm96"
  ciphertext_wo         = var.wrapped_ciphertext
  ciphertext_wo_version = 1
}
```

### Importing a New Key Version

To import new key material into the existing key, provide the new wrapped ciphertext and increment
`ciphertext_wo_version`. The ciphertext is sent to Vault only when `ciphertext_wo_version` changes, so
leaving `ciphertext_wo` in the configuration while editing other arguments does not create duplicate key versions.

```hcl
resource "vault_transit_secret_backend_imported_key" "example_byok" {
  mount                 = vault_mount.transit.path
  name                  = "my-imported-key"
  type                  = "aes256-gcm96"
  ciphertext_wo         = var.wrapped_ciphertext_v2
  ciphertext_wo_version = 2
}
```

For a public-key-only key, change `public_key` to import the new public key as a new version.

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where the Transit secret backend is mounted. Changing this forces a new resource.

* `name` - (Required) Name of the encryption key to create. Changing this forces a new resource.

* `type` - (Required) Specifies the type of key to create. Supported types: `aes128-gcm96`, `aes256-gcm96`, `chacha20-poly1305`, `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `hmac`, `aes128-cmac`, `aes192-cmac`, `aes256-cmac`. Changing this forces a new resource.

* `ciphertext_wo` - (Optional, Sensitive, Write-Only) A base64-encoded string containing the wrapped ephemeral AES key and the encrypted key material. Required when importing private or symmetric keys. Must be used together with `ciphertext_wo_version`. This field is write-only and is not stored in the Terraform plan or state, and is not read back from Vault. Vault requires either this or `public_key` for the initial import. It's recommended to use an ephemeral variable for this value so the ciphertext isn't kept in your configuration. A new key version is only imported when `ciphertext_wo_version` changes. Removing both arguments from the configuration plans a one-time in-place update to clear `ciphertext_wo_version` and does not change the key.

* `ciphertext_wo_version` - (Optional) Version identifier for `ciphertext_wo`. Ciphertext is sent to Vault on create and then only when this value changes. Increment it, along with providing the new `ciphertext_wo`, to import new key material as a new key version. Must be used together with `ciphertext_wo`.

* `public_key` - (Optional) A plaintext PEM public key to be imported for public-key-only import. Changing this imports the new public key as a new key version. Vault requires either this or `ciphertext_wo` for the initial import. Removing it from the configuration plans a one-time in-place update to clear it from state and does not change the key.

* `hash_function` - (Optional) The hash function used for the RSA-OAEP step of creating the ciphertext (`SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`). Vault uses `SHA256` if not set. Vault does not store this value; it is only used to unwrap the ciphertext in each request, so it is sent to Vault every time `ciphertext_wo` is sent (on create and whenever `ciphertext_wo_version` changes).

* `version` - (Optional) The existing key version to update when importing key material into an already-imported key. If omitted, Vault creates a new version, except when the latest version contains only a public key and the new ciphertext supplies its matching private key; in that case Vault adds the private key to that existing version. Ignored when the key is first imported.
  ~> **Note:** `version` is sent to Vault whenever key material is imported, so each time you bump `ciphertext_wo_version`, either remove `version` from the configuration (to target the latest version) or set it to the key version you want to add private key material to. Leaving a previous value in place targets that same version again.

* `import_version_type` - (Optional) Changes the key type of the new key version when importing key material into an existing key. The usage of the new type must match the usage of the existing type. Sent to Vault as `type` on the import key version endpoint, so it has no effect on the initial import. The result is shown in `latest_version_type`; `type` remains the original key type. *Available only for Vault Enterprise 2.2 or later*.

* `allow_rotation` - (Optional) If set to `true`, the imported key can be rotated within Vault using the rotate endpoint. Once the key is rotated in Vault, it no longer accepts imported key material. Changing this forces a new resource.

* `derived` - (Optional) Specifies if key derivation is to be used. Changing this forces a new resource.

* `context` - (Optional, Sensitive) A base64-encoded string providing a context for key derivation. Required if `derived` is true. Changing this forces a new resource.

* `deletion_allowed` - (Optional) Specifies if the key is allowed to be deleted. Must be set to `true` before the resource can be destroyed or replaced. Can be updated in place.

* `exportable` - (Optional) Enables keys to be exportable. Once set to `true`, this cannot be disabled. Can be updated in place.

* `allow_plaintext_backup` - (Optional) If set, enables taking backup of named key in plaintext format. Once set to `true`, this cannot be disabled. Can be updated in place.

* `auto_rotate_period` - (Optional) The period in seconds at which this key should be rotated automatically. Set to `0` to disable; otherwise it must be at least one hour (`3600`). Can be updated in place.

* `min_decryption_version` - (Optional) Minimum key version to use for decryption. Vault always sets this to at least `1`. Can be updated in place.

* `min_encryption_version` - (Optional) Minimum key version to use for encryption. Can be updated in place.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `min_available_version` - Minimum key version available for use.
* `imported_key` - Whether the key was imported into Vault (as opposed to generated by Vault).
* `imported_key_allow_rotation` - Whether the imported key is configured to allow rotation.
* `latest_version` - Latest key version in use in the keyring.
* `latest_version_type` - The key type of the latest key version in the keyring. *Available only for Vault 2.2 or later*.
* `supports_encryption` - Whether the key supports encryption.
* `supports_decryption` - Whether the key supports decryption.
* `supports_derivation` - Whether the key supports derivation.
* `supports_signing` - Whether the key supports signing.
* `keys` - Map of key version to its metadata in the keyring.

## Import

Transit keys can be imported using the `{mount}/keys/{name}` or `{mount}/{name}` format:

```
$ terraform import vault_transit_secret_backend_imported_key.example transit/keys/my-imported-key
```

~> **Note:** Vault does not return key material, so only the key metadata returned by Vault is set in state. **If your configuration sets `ciphertext_wo_version` or `public_key`, the next apply imports that key material as a new key version.** To only bring an existing imported key under Terraform management, leave these arguments out of the configuration.
