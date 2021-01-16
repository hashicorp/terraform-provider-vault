---
layout: "vault"
page_title: "Vault: vault_transform_role resource"
sidebar_current: "docs-vault-resource-transform-role"
description: |-
  "/transform/role/{name}"
---

# vault\_transform\_role

This resource supports the "/transform/role/{name}" Vault endpoint.

It creates or updates the role with the given name. If a role with the name does not exist, it will be created.
If the role exists, it will be updated with the new attributes.

## Example Usage

```hcl
resource "vault_mount" "mount_transform" {
  path = "transform"
  type = "transform"
}
resource "vault_transform_role" "test" {
  path = vault_mount.mount_transform.path
  name = "payments"
  transformations = ["ccn-fpe"]
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) Path to where the back-end is mounted within Vault.
* `name` - (Required) The name of the role.
* `transformations` - (Optional) A comma separated string or slice of transformations to use.
