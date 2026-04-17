---
layout: "vault"
page_title: "Vault: vault_activation_flags resource"
sidebar_current: "docs-vault-resource-activation-flags"
description: |-
  Manages activation flags in Vault.
---

# vault_activation_flags

Manages activation flags in Vault.

~> **Important** Activation flags are available only in Vault Enterprise and are managed through a singleton system endpoint.

~> **Important** Vault exposes activation for individual flags, but does not expose a public deactivation API. The `activated_flags` argument must therefore contain the full set of flags that should remain active.

## Example Usage

### Manage the Current Activated Set

```hcl
data "vault_activation_flags" "current" {}

resource "vault_activation_flags" "example" {
  activated_flags = data.vault_activation_flags.current.activated_flags
}
```

### Activate an Additional Flag

```hcl
data "vault_activation_flags" "current" {}

resource "vault_activation_flags" "example" {
  activated_flags = setunion(
    data.vault_activation_flags.current.activated_flags,
    toset(["my-feature-flag"]),
  )
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `activated_flags` - (Required) Full set of activation flag keys that should be active.
  Because Vault does not provide a public deactivation API for activation flags, any flags already active in Vault must also be included here.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The singleton activation flags resource ID. This value is always `activation-flags`.

## Import

The activation flags resource can be imported using the fixed ID, e.g.

```shell
$ terraform import vault_activation_flags.example activation-flags
```

## Notes

* This resource manages a singleton endpoint: only one `vault_activation_flags` resource should exist per Vault cluster.
* Destroying this resource removes it from Terraform state only. It does not deactivate flags already enabled in Vault.
* If Vault already has active flags that are omitted from `activated_flags`, Terraform returns an error instead of attempting deactivation.
* Activation flag names must exactly match the feature keys returned by `GET /sys/activation-flags`.