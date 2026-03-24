---
layout: "vault"
page_title: "Vault: vault_rotation_policy resource"
sidebar_current: "docs-vault-resource-rotation-policy"
description: |-
  Writes rotation policies for Vault
---

# vault_rotation_policy

Provides a resource to manage Rotation Policies.

**Note** this feature is available only in Vault Enterprise 2.0+.

## Example Usage

```hcl
resource "vault_rotation_policy" "example" {
  name = "database-admin-retry-policy"

  policy = jsonencode({
    max_retries_per_cycle = 6
    max_retry_cycles      = 3
  })
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `name` - (Required) The name of the rotation policy.

* `policy` - (Required) A non-empty JSON policy document string. Vault validates policy JSON and semantics.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Rotation policies can be imported using the `name`, e.g.

```
$ terraform import vault_rotation_policy.example database-admin-retry-policy
```
