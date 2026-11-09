---
layout: "vault"
page_title: "Vault: vault_transform_masking_transformation resource"
sidebar_current: "docs-vault-resource-transform-transformation-fpe-imported-key"
description: |-
  Creates a Transform masking transformation for replacing sensitive data with masking characters and manages its configuration in place.
---

Creates a Transform masking transformation used for replacing sensitive data with masking characters.

~> **Vault Enterprise only** The Transform secrets engine requires Vault Enterprise.

## Example Usage

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in. The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).

* `mount` - (Required) Path where the Transform secret backend is mounted. Changing this forces a new resource.

* `name` - (Required) Name of the transformation to create. Changing this forces a new resource.

* `template` - (Required) Name of the template to use to match values when encoding/decoding with this transformation.

* `masking_character` - (Optional) Specifies the character to use for masking. Must be a single character. Defaults to `*` when not set.

* `allowed_roles` - (Optional) A list of allowed roles that this transformation can be assigned to.