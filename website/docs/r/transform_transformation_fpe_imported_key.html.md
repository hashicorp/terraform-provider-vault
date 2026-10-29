---
layout: "vault"
page_title: "Vault: vault_transform_transformation_fpe_imported_key resource"
sidebar_current: "docs-vault-resource-transform-transformation-fpe-imported-key"
description: |-
  Creates a Transform format-preserving encryption (FPE) transformation from imported key material (BYOK) and manages its configuration in place.
---

# vault\_transform\_transformation\_fpe\_imported\_key

Creates a Transform format-preserving encryption (`fpe`) transformation from imported key material (BYOK) and manages the
transformation's ongoing configuration in place. To import key material for a tokenization transformation, use
[`vault_transform_transformation_tokenization_imported_key`](/docs/providers/vault/r/transform_transformation_tokenization_imported_key.html).

~> **Vault Enterprise only** The Transform secrets engine requires Vault Enterprise.

~> **Deletion protection** Terraform can delete this transformation during `terraform destroy` or resource replacement. Deleting and recreating it may interrupt clients, and imported key material may be lost. Keep `deletion_allowed` set to false unless you intentionally want to delete the transformation.

~> **Replacing key material** Vault cannot import new key material into an existing FPE transformation.

For more information, please refer to [the Vault Transform documentation](https://developer.hashicorp.com/vault/api-docs/secret/transform#import-key-for-fpe-transformation).

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

resource "vault_transform_template" "numeric" {
  path     = vault_mount.transform.path
  name     = "numeric-ssn"
  type     = "regex"
  pattern  = "(\\d{9})"
  alphabet = "builtin/numeric"
}

resource "vault_transform_transformation_fpe_imported_key" "example" {
  mount                 = vault_mount.transform.path
  name                  = "my-fpe"
  template              = vault_transform_template.numeric.name
  tweak_source          = "internal"
  ciphertext_wo         = var.wrapped_ciphertext
  ciphertext_wo_version = 1
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in. The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).

* `mount` - (Required) Path where the Transform secret backend is mounted. Changing this forces a new resource.

* `name` - (Required) Name of the transformation to create. Changing this forces a new resource.

* `template` - (Required) The name of the template to use. Can be updated in place.

* `ciphertext_wo` - (Optional, Sensitive, Write-Only) Base64-encoded wrapped key material. Must be used with `ciphertext_wo_version`. Terraform does not store or read this value back. It is required to create the transformation, but may be omitted when adopting one with `terraform import`. Use an ephemeral variable to keep it out of configuration.

* `ciphertext_wo_version` - (Optional) Version identifier for `ciphertext_wo`. Vault imports ciphertext on create; changing this value replaces the transformation. Removing it does not replace the resource. Required with `ciphertext_wo`.

* `hash_function` - (Optional) Hash function used to unwrap the ciphertext. The provider sends it with the ciphertext on create; Vault does not return it, so Terraform cannot verify it.

* `allowed_roles` - (Optional) The list of roles allowed to perform this transformation. Can be updated in place.

* `deletion_allowed` - (Optional) If `true`, the transformation can be deleted. Can be updated in place. The provider applies it after creation; after Terraform import, it is `false` in state, so setting it to `true` plans an in-place update.

* `tweak_source` - (Optional) The source of the tweak value: `supplied`, `generated` or `internal`. Can be updated in place.

* `max_tweak_len` - (Optional) The maximum tweak length in bytes, from `0` to `32`. Vault does not allow changes after creation; changing it fails at apply time.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `fpe_algorithm` - The FPE algorithm used by this transformation and set by Vault at creation time. New transformations use `ff1`. `ff3-1` is deprecated as of Vault 2.2.0 and only appears on existing transformations; migrate its data to an `ff1` transformation with [the Rewrap endpoint](https://developer.hashicorp.com/vault/api-docs/secret/transform#rewrap). 

## Import

Transformations can be imported using the `{mount}/transformation/{name}` or `{mount}/{name}` format:

```
$ terraform import vault_transform_transformation_fpe_imported_key.example transform/transformation/my-fpe
```

Importing a transformation whose type is not `fpe` fails.

~> **Note:** Vault does not report whether a transformation's key was imported. Use this resource only for transformations whose key was imported.

~> **Note:** Vault's import endpoint ignores `deletion_allowed`, so a transformation imported outside Terraform has `deletion_allowed = false` unless it was set with a later update. If your configuration sets `deletion_allowed = true`, the first plan after import shows an in-place update.
