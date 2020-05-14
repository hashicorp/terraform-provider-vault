---
layout: "vault"
page_title: "Vault: vault_transform_alphabet_name resource"
sidebar_current: "docs-vault-resource-transform-alphabet-name"
description: |-
  "/transform/alphabet/{name}"
---

# vault\_transform\_alphabet\_name

This resource supports the "/transform/alphabet/{name}" Vault endpoint.

It queries an existing alphabet by the given name.

## Example Usage

```hcl
resource "vault_mount" "mount_transform" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_alphabet_name" "test" {
  path = vault_mount.mount_transform.path
  name = "numerics"
  alphabet = "0123456789"
}
```

## Argument Reference

The following arguments are supported:
* `path` - (Required) Path to where the back-end is mounted within Vault.
* `alphabet` - (Optional) A string of characters that contains the alphabet set.
* `name` - (Required) The name of the alphabet.
