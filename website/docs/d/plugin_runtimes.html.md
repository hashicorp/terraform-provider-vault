---
layout: "vault"
page_title: "Vault: vault_plugin_runtimes data source"
sidebar_current: "docs-vault-datasource-plugin-runtimes"
description: |-
  Lists plugin runtimes from Vault's plugin runtimes catalog.
---

# vault\_plugin\_runtimes

Lists plugin runtimes registered in Vault's plugin runtimes catalog.

~> **Important** This data source requires Vault 1.15 or later.

## Example Usage

### List all plugin runtimes

```hcl
data "vault_plugin_runtimes" "all" {}
```

### Filter by runtime type

```hcl
data "vault_plugin_runtimes" "containers" {
  type = "container"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `type` - (Optional) The plugin runtime type to list. Currently only `container` is supported.

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `id` - Unique identifier for this data source. Values are:
  * `plugin-runtimes` when listing all runtime types.
  * `plugin-runtimes/{type}` when `type` is provided.

* `runtimes` - List of plugin runtimes. Each object contains:
  * `name` - The runtime name.
  * `type` - The runtime type.
  * `rootless` - Whether the runtime runs as a non-root user.
  * `oci_runtime` - The OCI runtime used for plugin containers, when set.
  * `cgroup_parent` - The parent cgroup for plugin containers, when set.
  * `cpu_nanos` - CPU quota in nanoseconds per second, when set.
  * `memory_bytes` - Memory limit in bytes, when set.
