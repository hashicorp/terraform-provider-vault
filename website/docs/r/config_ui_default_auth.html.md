---
layout: "vault"
page_title: "Vault: vault_config_ui_default_auth resource"
sidebar_current: "docs-vault-resource-config-ui-default-auth"
description: |-
  Manages UI default authentication configuration in Vault.
---

# vault\_config\_ui\_default\_auth

Manages the UI default authentication configuration for the Vault GUI login form. This resource configures which authentication method is displayed by default on the Vault UI login page, along with optional backup authentication methods that appear in the "Sign in with other methods" tab.

~> **Important** This feature is available only with Vault Enterprise 1.20.0 or later.

## Example Usage

### Basic Configuration

```hcl
resource "vault_config_ui_default_auth" "example" {
  name              = "my-auth-config"
  default_auth_type = "ldap"
}
```

### Configuration with Backup Methods

```hcl
resource "vault_config_ui_default_auth" "example" {
  name              = "my-auth-config"
  default_auth_type = "oidc"
  backup_auth_types = ["ldap", "userpass", "token"]
}
```

### Configuration for Specific Namespace

```hcl
resource "vault_config_ui_default_auth" "admin_config" {
  name              = "admin-auth-config"
  namespace_path    = "admin"
  default_auth_type = "ldap"
  backup_auth_types = ["token"]
}
```

### Configuration with Inheritance Disabled

```hcl
resource "vault_config_ui_default_auth" "parent_config" {
  name                = "parent-auth-config"
  namespace_path      = "parent"
  default_auth_type   = "oidc"
  backup_auth_types   = ["github", "token"]
  disable_inheritance = true
}
```

### Complete Configuration Example

```hcl
resource "vault_config_ui_default_auth" "complete" {
  name                = "complete-auth-config"
  namespace_path      = "engineering"
  default_auth_type   = "oidc"
  backup_auth_types   = ["ldap", "userpass", "token"]
  disable_inheritance = true
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Unique identifier for the configuration. Can contain letters, numbers, underscores, and dashes. Changing this forces resource recreation.

* `default_auth_type` - (Required) The default authentication method displayed on the Vault UI login page. Must be one of: `github`, `jwt`, `ldap`, `oidc`, `okta`, `radius`, `saml`, `token`, or `userpass`.

* `namespace_path` - (Optional) Target namespace for the configuration. When empty or omitted, applies to the root namespace. The value is normalized internally (e.g., "root" becomes "root/" for the API).

* `backup_auth_types` - (Optional) List of backup authentication methods displayed in the "Sign in with other methods" tab in the Vault UI. Each value must be a valid authentication type from the same list as `default_auth_type`. The order of methods is preserved as specified.

* `disable_inheritance` - (Optional) If `true`, child namespaces will not inherit the `default_auth_type` and `backup_auth_types` from this configuration. Defaults to `false`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The unique identifier for this resource, which matches the `name` value.

## Import

UI default authentication configurations can be imported using the `name`, e.g.

```
$ terraform import vault_config_ui_default_auth.example my-auth-config
```

### Importing with Namespaces

When importing a configuration that exists in a specific namespace, you must set the `TERRAFORM_VAULT_NAMESPACE_IMPORT` environment variable to ensure proper resource management:

```
$ export TERRAFORM_VAULT_NAMESPACE_IMPORT=admin
$ terraform import vault_config_ui_default_auth.example my-auth-config
```

Without setting the namespace during import, subsequent operations (update/delete) may target the wrong namespace and fail.

## Notes

* **Enterprise Only**: This resource requires Vault Enterprise 1.20.0 or later.

* **Authentication Methods**: The authentication methods specified in `default_auth_type` and `backup_auth_types` must be enabled in Vault before they can be used in the UI configuration. The resource validates that only supported auth types are used.

* **Root Namespace**: When `namespace_path` is empty, omitted, or set to "root", the configuration applies to the root namespace. The API normalizes these values to "root/" internally.

* **Order Preservation**: The order of methods in `backup_auth_types` is preserved and determines the display order in the Vault UI's "Sign in with other methods" tab.

* **Supported Auth Types**: The following authentication types are supported: `github`, `jwt`, `ldap`, `oidc`, `okta`, `radius`, `saml`, `token`, and `userpass`. These correspond to Vault's authentication methods.

## API Documentation

For more details on the underlying Vault API, see the [Vault UI Default Auth API documentation](https://developer.hashicorp.com/vault/api-docs/system/config-ui-login-default-auth).