---
layout: "vault"
page_title: "Vault: vault_activation_flags data source"
sidebar_current: "docs-vault-datasource-activation-flags"
description: |-
  Reads activation flags from Vault.
---

# vault_activation_flags

Reads activation flags from Vault.

~> **Important** Activation flags require Vault 1.16 or later.

~> **Important** Activation flags are available only in Vault Enterprise and are exposed through a singleton system endpoint.

~> **Important** The activation flags endpoint is root-namespace-only. This data source does not accept a `namespace` argument.

## Example Usage

```hcl
data "vault_activation_flags" "current" {}
```

## Argument Reference

This data source has no arguments.

## Attributes Reference

The following attributes are exported:

* `id` - Unique identifier for this data source. This value is always `sys/activation-flags`.

* `activated_flags` - Set of currently activated feature flag keys.

* `unactivated_flags` - Set of currently unactivated feature flag keys.

## Notes

* Activation flag names are returned exactly as reported by Vault.
* This data source reads from `GET /sys/activation-flags`.
* The provider returns both `activated_flags` and `unactivated_flags` as Terraform sets.