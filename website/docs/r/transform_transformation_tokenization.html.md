---
layout: "vault"
page_title: "Vault: vault_transform_transformation_tokenization resource"
sidebar_current: "docs-vault-resource-transform-transformation-tokenization"
description: |-
  "/transform/transformations/tokenization/{name}"
---

# vault\_transform\_transformation\_tokenization

This resource supports the "/transform/transformations/tokenization/{name}" Vault endpoint.

If a tokenization transformation with the given name doesn't exist, it will be created. If a tokenization transformation with the given name exists, it will be updated with the new attributes.

## Example Usage

```hcl
resource "vault_mount" "example" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_transformation_tokenization" "example" {
  path             = vault_mount.example.path
  name             = "tkn-example"
  max_ttl          = 86400
  deletion_allowed = true
  mapping_mode     = "default"
  allowed_roles    = ["payments"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Required) Path to where the back-end is mounted within Vault.
* `name` - (Required) Name of the transformation to create/update.
* `mapping_mode` - (Optional) Specifies the mapping mode for stored tokenization values.
  Can be `"default"` or `"exportable"`. `"default"` is strongly recommended for highest security.
  `"exportable"` allows for all plaintexts to be decoded via the export-decoded endpoint in an emergency.
  **Note:** This field is immutable and cannot be changed after creation. Changing this value will force recreation of the resource.
* `convergent` - (Optional) Specifies whether to use convergent tokenization, where tokenization of
  the same plaintext more than once results in the same token. Default is `false`.
  **Note:** This field is immutable and cannot be changed after creation. Changing this value will force recreation of the resource.
* `max_ttl` - (Optional) The maximum TTL of a token. If `0` or unspecified, tokens may have no expiration. Default is `0`.
* `allowed_roles` - (Optional) Specifies a list of allowed roles that this transformation can be assigned to.
  A role using this transformation must exist in this list in order for encode and decode operations to properly function. Default is `[]`.
* `stores` - (Optional) The list of tokenization stores to use for tokenization state. Default is `["builtin/internal"]`.
  **Note:** This field is immutable and cannot be changed after creation. Changing this value will force recreation of the resource.
* `deletion_allowed` - (Optional) If true, this transform can be deleted. Otherwise deletion is blocked while this value remains false. Note that deleting the transform deletes the underlying key, making decoding of tokenized values impossible without restoring from a backup. Default is `false`.
