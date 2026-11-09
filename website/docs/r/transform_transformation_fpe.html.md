---
layout: "vault"
page_title: "Vault: vault_transform_transformation_fpe resource"
sidebar_current: "docs-vault-resource-transform-transformation-fpe"
description: |-
  Creates and manages a Format Preserving Encryption (FPE) transformation in a Vault Transform secrets engine.
---

# vault\_transform\_transformation\_fpe

Creates and manages a Format Preserving Encryption (FPE) transformation in a Vault
[Transform secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transform).
This resource uses the `/transform/transformations/fpe/{name}` Vault endpoint.

~> **Important** The Transform secrets engine requires Vault Enterprise with the Advanced Data
Protection module. Deleting an FPE transformation deletes its underlying key, which makes values
encoded by it impossible to decode without restoring from a backup. Vault blocks deletion
until `deletion_allowed` is `true`.

~> **Note** Use either this resource or [`vault_transform_transformation`](transform_transformation.html)
to manage a given FPE transformation, not both.

## Example Usage

### Basic Example

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_transformation_fpe" "example" {
  mount    = vault_mount.transform.path
  name     = "ccn-fpe"
  template = "builtin/creditcardnumber"
  deletion_allowed = true
}
```

### Advanced Example

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_transformation_fpe" "example" {
  mount        = vault_mount.transform.path
  name         = "ccn-fpe"
  template     = "builtin/creditcardnumber"
  tweak_source = "internal"

  # Roles that may use this transformation for encode and decode operations.
  allowed_roles = ["payments", "billing"]

  # Maximum tweak size in bytes (Vault 2.2.0 and later). Cannot be changed after creation.
  max_tweak_len = 8

  # Required before Terraform can destroy the transformation.
  deletion_allowed = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where the Transform secrets engine is mounted.
  Changing this forces a new resource to be created.

* `name` - (Required) Name of the transformation.
  Changing this forces a new resource to be created.

* `template` - (Required) Name of the template used to match values on encode and decode operations.

* `tweak_source` - (Optional) Source of the tweak value. Valid values are `supplied`, `generated`
  and `internal`. If not set, Vault uses `supplied`.

* `allowed_roles` - (Optional) List of roles allowed to use this transformation. A role using this
  transformation must be in this list for encode and decode operations to work.

* `deletion_allowed` - (Optional) If `true`, this transformation can be deleted. Otherwise deletion
  is blocked while this value is `false`. Defaults to `false`.

* `max_tweak_len` - (Optional) Maximum tweak size, in bytes, allowed for this transformation.
  Valid values are `0` to `32`; `0` allows a tweak of any length. If not set, Vault uses `0`.
  Vault does not allow this value to be changed after creation, so changing it fails at apply
  time. Requires Vault 2.2.0 or later.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `fpe_algorithm` - The FPE algorithm used by this transformation, for example `ff1`. As of Vault
  2.2.0, new FPE transformations use FF1 and FF3-1 is deprecated.

## Import

An FPE transformation can be imported using the format `<mount>/<name>` or
`<mount>/transformation/<name>`, e.g.

```
$ terraform import vault_transform_transformation_fpe.example transform/ccn-fpe
```

Only transformations of type `fpe` can be imported. To import a resource in a namespace, set the
`TERRAFORM_VAULT_NAMESPACE_IMPORT` environment variable.
