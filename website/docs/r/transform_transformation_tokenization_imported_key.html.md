---
layout: "vault"
page_title: "Vault: vault_transform_transformation_tokenization_imported_key resource"
sidebar_current: "docs-vault-resource-transform-transformation-tokenization-imported-key"
description: |-
  Creates a Transform tokenization transformation from imported key material (BYOK) and manages its key versions and configuration in place.
---

# vault\_transform\_transformation\_tokenization\_imported\_key

Creates a Transform `tokenization` transformation from imported key material (BYOK) and manages the
transformation's key versions and ongoing configuration in place. To import key material for a
format-preserving encryption transformation, use
[`vault_transform_transformation_fpe_imported_key`](/docs/providers/vault/r/transform_transformation_fpe_imported_key.html).

~> **Vault Enterprise only** The Transform secrets engine requires Vault Enterprise.

~> **Deletion protection** Terraform can delete this transformation during `terraform destroy` or resource replacement. Deleting and recreating it may interrupt clients, and imported key material may be lost. Keep `deletion_allowed` set to false unless you intentionally want to delete the transformation.

~> **Importing key versions** New versions can be imported only while the key remains imported and has not been rotated in Vault.

For more information, please refer to [the Vault Transform documentation](https://developer.hashicorp.com/vault/api-docs/secret/transform#import-key-for-tokenization-transformation).

## Example Usage

Use the [`vault_transform_wrapping_key`](/docs/providers/vault/d/transform_wrapping_key.html) data source to read the mount's public wrapping key.

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}

data "vault_transform_wrapping_key" "wrapping_key" {
  mount = vault_mount.transform.path
}

resource "vault_transform_transformation_tokenization_imported_key" "example" {
  mount                 = vault_mount.transform.path
  name                  = "my-tokenization"
  ciphertext_wo         = var.wrapped_ciphertext
  ciphertext_wo_version = 1
  allowed_roles         = ["payments"]
  max_ttl               = 3600
}
```

### Importing a New Key Version

To import a key version, update `ciphertext_wo` and `ciphertext_wo_version` in the same apply.

```hcl
resource "vault_transform_transformation_tokenization_imported_key" "example" {
  mount                 = vault_mount.transform.path
  name                  = "my-tokenization"
  ciphertext_wo         = var.wrapped_ciphertext_v2
  ciphertext_wo_version = 2
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).

* `mount` - (Required) Path where the Transform secret backend is mounted. Changing this forces a new resource.

* `name` - (Required) Name of the transformation to create. Changing this forces a new resource.

* `ciphertext_wo` - (Optional, Sensitive, Write-Only) Base64-encoded wrapped key material. Terraform does not store or read this value back. It is required to create the transformation, but may be omitted when adopting one with `terraform import`. Use an ephemeral variable to keep it out of configuration.

* `ciphertext_wo_version` - (Optional) Version trigger for `ciphertext_wo`. Terraform sends the ciphertext on create and, in place, only when this value changes. Change it with new ciphertext in the same apply; changing `ciphertext_wo` alone has no effect. Removing both arguments clears the version from state without changing the transformation. Required with `ciphertext_wo`.

* `hash_function` - (Optional) Hash function used to unwrap the ciphertext. The provider sends it with each ciphertext import; Vault does not return it, so Terraform cannot verify it.

* `allow_rotation` - (Optional) If `true`, allows key rotation. The provider applies this setting on create only and Vault does not report it on read; setting it for an existing transformation forces replacement.

* `allowed_roles` - (Optional) Roles allowed to use this transformation. Can be updated in place.

* `deletion_allowed` - (Optional) If `true`, the transformation can be deleted. Can be updated in place. The provider applies it after creation; after Terraform import, it is `false` in state, so setting it to `true` plans an in-place update.

* `mapping_mode` - (Optional) The mapping mode for stored tokenization values: `default` or `exportable`. Vault uses `default` if unset and does not allow changes after creation. Terraform does not replace the resource for changes, so they fail at apply time.

* `max_ttl` - (Optional) Maximum token TTL in seconds. Can be updated in place.

* `stores` - (Optional) Stores that contain tokenized state. Can be updated in place.

* `min_decryption_version` - (Optional) Minimum key version to use for decryption. Can be updated in place.

* `auto_rotate_period` - (Optional) Automatic rotation period in seconds. Can be updated in place.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `latest_version` - Latest key version in use.
* `min_available_version` - Minimum key version available for use.

## Import

Transformations can be imported using the `{mount}/transformation/{name}` or `{mount}/{name}` format:

```
$ terraform import vault_transform_transformation_tokenization_imported_key.example transform/transformation/my-tokenization
```

Importing a transformation whose type is not `tokenization` fails.

~> **Note:** Vault does not report whether a transformation's key was imported. Use this resource only for imported keys. To adopt an existing transformation without importing another key version, omit `ciphertext_wo` and `ciphertext_wo_version`.

