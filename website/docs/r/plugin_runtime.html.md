---
layout: "vault"
page_title: "Vault: vault_plugin_runtime resource"
sidebar_current: "docs-vault-resource-plugin-runtime"
description: |-
  Manages plugin runtimes in Vault's plugin runtime catalog.
---

# vault\_plugin\_runtime

Manages a plugin runtime in Vault's plugin runtime catalog. Plugin runtimes allow Vault to run plugins in isolated environments with resource constraints.

~> **Important** This resource requires Vault 1.15 or later.

## Example Usage

```hcl
resource "vault_plugin_runtime" "example" {
  type        = "container"
  name        = "example-runtime"
  oci_runtime = "runc"
  rootless    = false
}
```

### With Resource Limits

```hcl
resource "vault_plugin_runtime" "constrained" {
  type         = "container"
  name         = "constrained-runtime"
  oci_runtime  = "runc"
  cpu_nanos    = 1000000000  # 1 CPU core
  memory_bytes = 536870912   # 512 MB
  rootless     = true
}
```

### With Custom Cgroup

```hcl
resource "vault_plugin_runtime" "custom_cgroup" {
  type           = "container"
  name           = "custom-cgroup-runtime"
  oci_runtime    = "runc"
  cgroup_parent  = "/vault/plugins"
  cpu_nanos      = 2000000000  # 2 CPU cores
  memory_bytes   = 1073741824  # 1 GB
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
  *Available only for Vault Enterprise*.

* `type` - (Required) The type of plugin runtime. Currently only `container` is supported.
  Changing this forces a new resource to be created.

* `name` - (Required) The name of the plugin runtime.
  Changing this forces a new resource to be created.

* `oci_runtime` - (Optional) The OCI-compliant runtime to use for running plugin containers.
  Common values include `runc` (default) and `runsc` (gVisor).

* `cgroup_parent` - (Optional) The parent cgroup to set for each container.
  If not specified, defaults to the cgroup of the Vault process.

* `cpu_nanos` - (Optional) CPU time in nanoseconds that the plugin can use per second.
  For example, `1000000000` equals 1 CPU core. This sets a CPU quota for the container.

* `memory_bytes` - (Optional) Maximum memory in bytes that the plugin can use.
  For example, `536870912` equals 512 MB. This sets a memory limit for the container.

* `rootless` - (Optional) Whether the runtime should run the plugin as a non-root user.
  Defaults to `false`. When set to `true`, enhances security by running containers without root privileges.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The ID of the plugin runtime in the format `{type}/{name}`.

## Import

Plugin runtimes can be imported using the `{type}/{name}` format, e.g.

```
$ terraform import vault_plugin_runtime.example container/example-runtime
```

~> **Note on Import Behavior** The Vault API returns all configuration fields when reading a plugin runtime. However, fields that were not explicitly set (`oci_runtime`, `cgroup_parent`, `cpu_nanos`, `memory_bytes`) will have default values (empty string for strings, 0 for integers). The provider treats these default values as "not set" (null in Terraform state) to match configurations where these fields are omitted. After import, if your configuration includes these fields with non-default values, they will be properly populated in state.

**Import Workflow:**
1. Import the resource: `terraform import vault_plugin_runtime.example container/example-runtime`
2. Verify the import: `terraform plan` (should show no changes if config matches what's in Vault)

## Notes

* Plugin runtimes require Vault 1.15 or later
* The `container` runtime type requires a properly configured container runtime (e.g., Docker, containerd) on the Vault server
* Resource limits (`cpu_nanos`, `memory_bytes`) help prevent plugins from consuming excessive resources
* The `rootless` option provides additional security isolation but may have compatibility limitations with some plugins
* Deleting a plugin runtime that is in use by registered plugins will fail; you must first unregister or update those plugins