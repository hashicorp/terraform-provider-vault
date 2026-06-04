---
layout: "vault"
page_title: "Vault: vault_config_group_policy_application resource"
sidebar_current: "docs-vault-resource-config-group-policy-application"
description: |-
  Manages the global group policy application mode in Vault Enterprise.
---

# vault\_config\_group\_policy\_application

Manages the global group policy application mode for Vault Enterprise. This resource controls how policies attached to identity groups are applied across namespace boundaries.

**Important:** This is a singleton resource - only one instance can exist per Vault cluster. The resource must be managed from the root or administrative namespace.

**Note** this feature is available only with Vault Enterprise 1.13.8+.

## Example Usage

### Basic Usage (Root Namespace)

```hcl
# Configure group policy application mode in root namespace
# Using the default mode
resource "vault_config_group_policy_application" "test" {
  group_policy_application_mode = "within_namespace_hierarchy"
}

```

### Using "any" Mode

```hcl
resource "vault_config_group_policy_application" "config" {
  group_policy_application_mode = "any"
}
```

### Explicit Root Namespace

```hcl
resource "vault_config_group_policy_application" "config" {
  group_policy_application_mode = "within_namespace_hierarchy"
}
```

### Administrative Namespace

When working with an administrative namespace, you can specify it directly in the resource:

```hcl
resource "vault_config_group_policy_application" "config" {
  group_policy_application_mode = "within_namespace_hierarchy"
  namespace                     = "admin"
}
```

## Argument Reference

The following arguments are supported:

* `group_policy_application_mode` - (Required) Mode for group policy application. Must be either `within_namespace_hierarchy` or `any`. Defaults to `within_namespace_hierarchy`.
  - `within_namespace_hierarchy`: Policies only apply when the token authorizing a request was created in the same namespace as the group, or a descendant namespace.
  - `any`: Group policies apply to all members of a group, regardless of what namespace the request token came from.

* `namespace` - (Optional) Target namespace. Must be root (`""`) or administrative (`"admin"`) namespace. If omitted, the provider's configured namespace is used.
  Set this to `""` to explicitly target the root namespace. The value should not contain leading or trailing forward slashes.
  *Available only for Vault Enterprise*.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The resource ID (always `"sys/config/group-policy-application"`).

## Import

The group policy application configuration can be imported using the path `sys/config/group-policy-application`:

```
$ terraform import vault_config_group_policy_application.config sys/config/group-policy-application
```

## Behavior Notes

### Singleton Resource

This resource is a singleton, meaning only one instance can exist per Vault cluster. Multiple `vault_config_group_policy_application` resources in your Terraform configuration will conflict.

### Deletion Behavior

When this resource is destroyed via `terraform destroy`, it does not delete the configuration from Vault. Instead, it resets the mode to the default value `within_namespace_hierarchy`. This ensures that Vault always has a valid group policy application mode configured.

### Namespace Requirements

This resource can only be managed from:
- The root namespace
- The administrative namespace (`"admin"`)

Attempting to manage this resource from any other namespace will result in an error.

### Policy Application Scope

**Important:** The group policy application mode only applies to ACL policies and no longer affects Sentinel RGPs for Vault ≥ 1.13.8, 1.14.4, 1.15.0.

### Replication Behavior

This configuration will be replicated between primary and secondary clusters. Primaries cannot have a different mode than secondaries.

## Version Requirements

- Requires Vault Enterprise 1.15.0 or later (TFVP support)