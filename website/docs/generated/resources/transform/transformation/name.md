---
layout: "vault"
page_title: "Vault: vault_transform_transformation_name resource"
sidebar_current: "docs-vault-resource-transform-transformation-name"
description: |-
  "/transform/transformation/{name}"
---

# vault\_transform\_transformation\_name

This resource supports the "/transform/transformation/{name}" Vault endpoint.

It creates or updates a transformation with the given name. If a transformation with the name does not exist, 
it will be created. If the transformation exists, it will be updated with the new attributes.

## Example Usage

```hcl
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}
resource "vault_transform_transformation_name" "test" {
  path = vault_mount.mount_transform.path
  name = "%s"
  type = "%s"
  template = "%s"
  tweak_source = "%s"
  allowed_roles = ["%s"]
  masking_character = "%s"
}
```

## Argument Reference

The following arguments are supported:
* `path` - (Required) Path to where the back-end is mounted within Vault.
* `allowed_roles` - (Optional) The set of roles allowed to perform this transformation.
* `masking_character` - (Optional) The character used to replace data when in masking mode
* `name` - (Required) The name of the transformation.
* `template` - (Optional) The name of the template to use.
* `templates` - (Optional) Templates configured for transformation.
* `tweak_source` - (Optional) The source of where the tweak value comes from. Only valid when in FPE mode.
* `type` - (Optional) The type of transformation to perform.
