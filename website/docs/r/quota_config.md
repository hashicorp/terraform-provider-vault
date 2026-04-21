---
layout: "vault"
page_title: "Vault: vault_quota_config resource"
sidebar_current: "docs-vault-quota-config"
description: |-
  Manage the singleton quota configuration.
---

# vault\_quota\_config

Manages the singleton quota configuration at `/sys/quotas/config`.

~> **Important** This is a global singleton configuration. Do not define this resource multiple times for the same Vault server, because each instance targets the same remote configuration.

~> **Important** Vault Enterprise allows `/sys/quotas/config` to be called from the root or an administrative namespace, but that support is asymmetric. Administrative namespaces can read the configuration and update the boolean flags, while the exempt-path fields remain effectively root-managed.

## Example Usage

```hcl
resource "vault_quota_config" "global" {
  namespace = "ns_admin"

  enable_rate_limit_audit_logging    = true
  enable_rate_limit_response_headers = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
  Vault Enterprise allows `/sys/quotas/config` to be called from the root or an administrative namespace, but support is asymmetric: administrative namespaces can update the boolean fields, while exempt-path management is effectively root-only.
  *Available only for Vault Enterprise*.

* `rate_limit_exempt_paths` - (Optional) Set of paths exempt from rate limit quotas relative to the current namespace context. Ordering is ignored. Terraform only sends this field when it is explicitly configured. In practice, exempt-path management is effectively root-only for this endpoint.

* `absolute_rate_limit_exempt_paths` - (Optional) Set of absolute paths exempt from all rate limit quotas, qualified from the root of the namespace hierarchy. Ordering is ignored. Terraform only sends this field when it is explicitly configured. In practice, this field is effectively root-managed; administrative namespaces can read returned values but cannot reliably manage them.

* `enable_rate_limit_audit_logging` - (Optional) Enables audit logging for requests rejected by rate limit quotas. Terraform only sends this field when it is explicitly configured. If omitted, Vault keeps its current value.

* `enable_rate_limit_response_headers` - (Optional) Enables rate limit response headers on HTTP responses. Terraform only sends this field when it is explicitly configured. If omitted, Vault keeps its current value.

## Attributes Reference

No additional attributes are exported by this resource.

## Delete Behavior

Vault does not expose a DELETE operation for `/sys/quotas/config`. Destroying this resource resets the configuration to the Vault defaults by writing:

* `rate_limit_exempt_paths = []`
* `absolute_rate_limit_exempt_paths = []`
* `enable_rate_limit_audit_logging = false`
* `enable_rate_limit_response_headers = false`

This reset behavior is supported only when the resource is managed from the root namespace. Destroying a namespaced `vault_quota_config` resource is not supported, because administrative namespaces cannot reset the root-managed exempt-path fields. To remove a namespaced instance from Terraform, first reset the quota configuration from the root namespace if needed, then remove the resource from state.

## Import

Import the singleton configuration with the fixed endpoint identifier:

```
$ terraform import vault_quota_config.global sys/quotas/config
```

When importing a namespaced instance, set `TERRAFORM_VAULT_NAMESPACE_IMPORT` so Terraform records the namespace in state:

```shell
$ TERRAFORM_VAULT_NAMESPACE_IMPORT=ns_admin terraform import vault_quota_config.global sys/quotas/config
```