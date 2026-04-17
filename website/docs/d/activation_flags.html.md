---
layout: "vault"
page_title: "Vault: vault_activation_flags data source"
sidebar_current: "docs-vault-datasource-activation-flags"
description: |-
  Reads activation flags from Vault.
---

# vault_activation_flags

Reads activation flags from Vault.

~> **Important** Activation flags are available only in Vault Enterprise and are exposed through a singleton system endpoint.

## Example Usage

```hcl
data "vault_activation_flags" "current" {}
```

### Use the Current Activated Set in a Resource

```hcl
data "vault_activation_flags" "current" {}

resource "vault_activation_flags" "example" {
  activated_flags = data.vault_activation_flags.current.activated_flags
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

## Attributes Reference

In addition to the argument above, the following attributes are exported:

* `id` - Unique identifier for this data source. This value is always `sys/activation-flags`.

* `activated_flags` - Set of currently activated feature flag keys.

* `unactivated_flags` - Set of currently unactivated feature flag keys.

## Notes

* Activation flag names are returned exactly as reported by Vault.
* This data source reads from `GET /sys/activation-flags`.
* The provider returns both `activated_flags` and `unactivated_flags` as Terraform sets.