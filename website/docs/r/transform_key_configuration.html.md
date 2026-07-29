---
layout: "vault"
page_title: "Vault: vault_transform_key_configuration resource"
sidebar_current: "docs-vault-resource-transform-key-configuration"
description: |-
  "/transform/tokenization/keys/{name}/config"
---

# vault\_transform\_key\_configuration

This resource supports the "/transform/tokenization/keys/{name}/config" Vault endpoint.

It updates the configuration for a key used in a transform. It only supports tokenization transforms.

## Example Usage

```hcl
resource "vault_mount" "mount_transform" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_key_configuration" "test" {
  path = vault_mount.mount_transform.path
  name = "credit-card"
  auto_rotate_period = "48h"
  min_decryption_version = 2
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) Path to where the back-end is mounted within Vault.
* `name` - (Required) Specifies the transform name to use for this operation.
* `min_decryption_version` - (Optional) Specifies the minimum key version that vault can use to decode values for the corresponding transform.
* `auto_rotate_period` - (Optional) The period at which this key should be rotated automatically. Setting this to "0" will disable automatic key rotation. This value cannot be shorter than one hour. Uses [duration format](https://developer.hashicorp.com/vault/docs/concepts/duration-format) strings.

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `min_available_version` - Minimum key version available for use.
* `latest_version` - Latest key version available for use.