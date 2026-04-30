---
layout: "vault"
page_title: "Vault: vault_activation_flags resource"
sidebar_current: "docs-vault-resource-activation-flags"
description: |-
  Manages activation flags in Vault.
---

# vault_activation_flags

Activates a single activation flag in Vault.

~> **Important** Activation flags require Vault 1.16 or later.

~> **Important** Activation flags are available only in Vault Enterprise.

~> **Important** The activation flags endpoint is root-namespace-only. This resource does not accept a `namespace` argument.

~> **Important** Vault exposes activation for individual flags at `PUT /sys/activation-flags/:feature/activate`, but does not expose a public deactivation API.

## Example Usage

### Activate a Feature

```hcl
resource "vault_activation_flags" "example" {
  feature = "secrets-sync"
}
```

## Argument Reference

The following arguments are supported:

* `feature` - (Required) Exact activation flag key to activate.
  The value must match a feature name returned by `GET /sys/activation-flags`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The activated feature key. This is the same value as `feature`.

## Import

The activation flags resource can be imported using the feature key, e.g.

```shell
$ terraform import vault_activation_flags.example secret_sync
```

## Notes

* Each `vault_activation_flags` resource activates exactly one feature by calling `PUT /sys/activation-flags/:feature/activate`.
* Destroying this resource removes it from Terraform state only. It does not deactivate the flag in Vault.
* Activation flag names must exactly match the feature keys returned by `GET /sys/activation-flags`.