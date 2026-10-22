---
layout: "vault"
page_title: "Vault: vault_transit_secret_backend_key_import_version resource"
sidebar_current: "docs-vault-resource-transit-secret-backend-key-import-version"
description: |-
  Imports new key material into an existing Transit key for Vault.
---

# vault\_transit\_secret\_backend\_key\_import\_version

Imports new key material into an existing imported Transit encryption key.

For more information, please refer to [the Vault Transit documentation](https://developer.hashicorp.com/vault/api-docs/secret/transit#import-key-version).

## Example Usage

### Import a new public key version

```hcl
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key_import" "example" {
  mount      = vault_mount.transit.path
  name       = "my-key"
  type       = "ecdsa-p256"
  public_key = file("${path.module}/public_v1.pem")
}

resource "vault_transit_secret_backend_key_import_version" "v2" {
  mount      = vault_transit_secret_backend_key_import.example.mount
  key_name   = vault_transit_secret_backend_key_import.example.name
  public_key = file("${path.module}/public_v2.pem")
}
```

### Import a new private/symmetric key version using ciphertext

Private and symmetric keys must be wrapped before import. See the [Transit key wrapping guide](https://developer.hashicorp.com/vault/docs/secrets/transit/key-wrapping-guide) for how to produce the wrapped payload.

The ciphertext field `ciphertext_wo` is write-only so its value is never stored in Terraform state, which means Terraform cannot detect when the wrapped payload changes. Use `ciphertext_wo_version` as an explicit change trigger: increment it each time you provide new wrapped key material.

```hcl
resource "vault_transit_secret_backend_key_import_version" "aes_v2" {
  mount    = vault_mount.transit.path
  key_name = vault_transit_secret_backend_key_import.example.name

  # Wrapped key material produced out-of-band. Never stored in Terraform state.
  ciphertext_wo = var.wrapped_key_material

  # Increment to trigger a new import when the wrapped key material changes.
  ciphertext_wo_version = 2
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where the Transit secret backend is mounted. Changing this forces a new resource.

* `key_name` - (Required) Name of the existing Transit encryption key to import key material into. Changing this forces a new resource.

* `ciphertext_wo` - (Optional, Sensitive, Write-only) A base64-encoded string containing the wrapped ephemeral AES key and the encrypted key material. Required when importing private or symmetric keys. Must be used together with `ciphertext_wo_version`.

* `ciphertext_wo_version` - (Optional) Version identifier for ciphertext updates. Increment this value to trigger importing a new key version in Vault. Must be used together with `ciphertext_wo`.

* `public_key` - (Optional) A plaintext PEM public key to be imported.

* `hash_function` - (Optional) The hash function used for the RSA-OAEP step of creating the ciphertext (`SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`). Defaults to `SHA256`.

* `version` - (Optional, Computed) Key version to update. If omitted, Vault creates a new version, except when the latest version contains only a public key and the request supplies its matching private key. In that case, Vault adds the private key to the existing, latest version.

## Attributes Reference

The following attributes are exported:

* `latest_version` - The latest version number of this key.

## Import

Transit key versions can be imported using `{mount}/keys/{key_name}/version/{version}` or `{mount}/{key_name}/{version}`:

```
$ terraform import vault_transit_secret_backend_key_import_version.example transit/keys/my-key/version/2
```
