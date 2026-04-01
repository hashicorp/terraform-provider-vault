---
layout: "vault"
page_title: "Vault: vault_config_group_policy_application resource"
sidebar_current: "docs-vault-resource-config-group-policy-application"
description: |-
  Manages the global group policy application mode for Vault Enterprise.
---

# vault\_config\_group\_policy\_application

Manages the global group policy application mode for Vault Enterprise. This resource controls how policies attached to identity groups are applied across namespace boundaries.

~> **Important:** This is a singleton resource - only one instance should exist per Vault cluster. The resource must be managed from the root (`""`) or administrative (`"admin"`) namespace.

~> **Enterprise Only:** This resource requires Vault Enterprise version 1.13.8 or later.

## Example Usage

### Set group policy application to "any" mode

```hcl
resource "vault_config_group_policy_application" "config" {
  group_policy_application_mode = "any"
}
```

### Use default mode explicitly

```hcl
resource "vault_config_group_policy_application" "config" {
  group_policy_application_mode = "within_namespace_hierarchy"
}
```

### Configure in administrative namespace

```hcl
resource "vault_config_group_policy_application" "config" {
  group_policy_application_mode = "any"
  namespace                     = "admin"
}
```

## Argument Reference

The following arguments are supported:

* `group_policy_application_mode` - (Required) Mode for group policy application. Must be either:
  * `"within_namespace_hierarchy"` (default) - Policies only apply when the token authorizing a request was created in the same namespace as the group, or a descendent namespace. This is the historical behavior and maintains strict namespace isolation.
  * `"any"` - Group policies apply to all members of a group, regardless of what namespace the request token came from. This relaxes namespace boundaries and is useful for shared identity groups across namespaces.

* `namespace` - (Optional) Target namespace. Must be root (`""`) or administrative (`"admin"`) namespace. Defaults to root namespace.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The resource ID (always `"config"`).

## Import

The group policy application configuration can be imported using the constant ID `config`:

```
$ terraform import vault_config_group_policy_application.config config
```

## Mode Descriptions

### within_namespace_hierarchy (Default)

This is the historical behavior that maintains strict namespace isolation:

* Policies attached to identity groups only apply when the token authorizing a request was created in the same namespace as the group, or a descendent namespace
* Recommended for multi-tenant environments where namespace isolation is critical
* Provides the most restrictive security posture

### any

This mode relaxes namespace boundaries:

* Group policies apply to all members of a group, regardless of what namespace the request token came from
* Useful for shared identity groups that need to work across multiple namespaces
* Should be carefully considered for security implications in multi-tenant environments

## Important Notes

* **Singleton Resource**: Only one instance of this resource should exist per Vault cluster
* **Namespace Restriction**: Must be managed from root (`""`) or administrative (`"admin"`) namespace
* **Enterprise Only**: Requires Vault Enterprise 1.13.8 or later
* **Replication**: Configuration is replicated between primary and secondary clusters
* **Global Impact**: Changing the mode affects all groups across all namespaces
* **Delete Behavior**: Deleting this resource resets the configuration to the default value (`"within_namespace_hierarchy"`) rather than removing it

## Security Considerations

When changing from `"within_namespace_hierarchy"` to `"any"`:

1. **Test in non-production first**: Understand the impact on your specific namespace hierarchy
2. **Review group memberships**: Ensure you understand which users will gain additional access
3. **Audit existing policies**: Review policies attached to groups that span namespaces
4. **Monitor audit logs**: Watch for unexpected access patterns after the change
5. **Document the decision**: Record why `"any"` mode is needed for your use case

## Migration from vault_generic_endpoint

If you're currently managing this configuration using `vault_generic_endpoint`, you can migrate to this dedicated resource:

```hcl
# Before (using generic_endpoint)
resource "vault_generic_endpoint" "group_policy" {
  path = "sys/config/group-policy-application"
  data_json = jsonencode({
    group_policy_application_mode = "any"
  })
}

# After (using dedicated resource)
resource "vault_config_group_policy_application" "config" {
  group_policy_application_mode = "any"
}
```

Migration steps:

1. Add the new `vault_config_group_policy_application` resource to your configuration
2. Import the existing configuration: `terraform import vault_config_group_policy_application.config config`
3. Remove the old `vault_generic_endpoint` resource from your configuration
4. Run `terraform plan` to verify no changes are needed

## See Also

* [Vault Group Policy Application API Documentation](https://developer.hashicorp.com/vault/api-docs/system/config-group-policy-application)
* [Vault Identity Groups Documentation](https://developer.hashicorp.com/vault/docs/secrets/identity)
* [Vault Namespaces Documentation](https://developer.hashicorp.com/vault/docs/enterprise/namespaces)