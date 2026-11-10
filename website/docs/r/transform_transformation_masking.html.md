---
layout: "vault"
page_title: "Vault: vault_transform_transformation_masking resource"
sidebar_current: "docs-vault-resource-transform-transformation-masking"
description: |-
  Creates a Transform masking transformation for replacing sensitive data with masking characters and manages its configuration in place.
---

# vault\_transform\_transformation\_masking

Creates a Transform masking transformation used for replacing sensitive data with masking characters.
Masking is one-way: values that are masked cannot be decoded back to the original data.

~> **Vault Enterprise only** The Transform secrets engine requires Vault Enterprise.

For more information, please refer to [the Vault Transform documentation](https://developer.hashicorp.com/vault/api-docs/secret/transform).

## Example Usage

### Basic Example

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_template" "ssn" {
  path     = vault_mount.transform.path
  name     = "ssn-template"
  type     = "regex"
  pattern  = "(\\d{3})-(\\d{2})-(\\d{4})"
  alphabet = "builtin/numeric"
}

resource "vault_transform_transformation_masking" "example" {
  mount    = vault_mount.transform.path
  name     = "ssn-mask"
  template = vault_transform_template.ssn.name
}
```

### Advanced Example

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_template" "ssn" {
  path     = vault_mount.transform.path
  name     = "ssn-template"
  type     = "regex"
  pattern  = "(\\d{3})-(\\d{2})-(\\d{4})"
  alphabet = "builtin/numeric"
}

resource "vault_transform_transformation_masking" "advanced" {
  mount             = vault_mount.transform.path
  name              = "ssn-mask-custom"
  template          = vault_transform_template.ssn.name
  masking_character = "#"
  allowed_roles     = ["payments", "support"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in. The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).

* `mount` - (Required) Path where the Transform secret backend is mounted. Changing this forces a new resource.

* `name` - (Required) Name of the transformation to create. Changing this forces a new resource.

* `template` - (Required) Name of the template to use to match values when encoding/decoding with this transformation. Can be updated in place.

* `masking_character` - (Optional) Specifies the character to use for masking. Must be a single character. Defaults to `*` when not set. Can be updated in place. Removing this argument later keeps the current character. Can be updated in place.

* `allowed_roles` - (Optional) A list of allowed roles that this transformation can be assigned to. Defaults to an empty list when not set. Can be updated in place.

## Attributes Reference

This resource exports no attributes in addition to the arguments above.

## Import

Transformations can be imported using the `{mount}/transformation/{name}` or `{mount}/{name}` format:

```
$ terraform import vault_transform_transformation_masking.example transform/transformation/ssn-mask
$ terraform import vault_transform_transformation_masking.example transform/ssn-mask
```

Importing a transformation whose type is not `masking` fails.
