---
layout: "vault"
page_title: "Vault: vault_secrets_sync_config resource"
sidebar_current: "docs-vault-secrets-sync-config"
description: |-
  Configures the secret sync global config.
---

# vault\_secrets\_sync\_config

Configures the secret sync global config. 
The config is global and can only be managed in the root namespace.

~> **Important** The config is global so the vault_secrets_sync_config resource must not be defined
multiple times for the same Vault server. If multiple definition exists, the last one applied will be
effective.

## Example Usage

```hcl
resource "vault_secrets_sync_config" "global_config" {
  disabled       = true
  queue_capacity = 500000
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  This resource can only be configured in the root namespace.
  *Available only for Vault Enterprise*.

* `disabled` - (Optional) Disables the syncing process between Vault and external destinations. Defaults to `false`.

* `queue_capacity` - (Optional) Maximum number of pending sync operations allowed on the queue. Defaults to `1000000`.


## Attributes Reference

No additional attributes are exported by this resource.

## Import

```
$ terraform import vault_secrets_sync_config.config global_config
```
