---
layout: "vault"
page_title: "Vault: vault_config_control_group resource"
sidebar_current: "docs-vault-resource-config-control-group"
description: |-
  Manages Control Group configuration in Vault.
---

# vault\_config\_control\_group

Manages the Control Group configuration in Vault. This endpoint is used to configure Control Group settings.

**Note** this feature is available only with Vault Enterprise.

## Example Usage

```hcl
resource "vault_config_control_group" "example" {
  max_ttl = "24h"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `max_ttl` - (Required) The maximum TTL for a control group wrapping token. This value can be specified as a duration string (e.g., "24h", "1h30m") or as an integer number of seconds (e.g., "86400").

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The path of the control group configuration endpoint (`sys/config/control-group`).

## Import

Control Group configuration can be imported using the path `sys/config/control-group`, e.g.

```
terraform import vault_config_control_group.example sys/config/control-group
```
