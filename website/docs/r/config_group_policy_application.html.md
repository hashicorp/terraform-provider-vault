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
terraform {
  required_providers {
    vault = {
      source = "hashicorp/vault"
    }
  }
}

provider "vault" {
  # Configuration is read from environment variables:
  # VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE
  # Example: export VAULT_ADDR="http://127.0.0.1:8200"
  # Example: export VAULT_TOKEN="your-token-here"
}

# Configure group policy application mode in root namespace
# Using the default mode
resource "vault_config_group_policy_application" "test" {
  group_policy_application_mode = "within_namespace_hierarchy"
}

# Outputs
output "mode" {
  value = vault_config_group_policy_application.test.group_policy_application_mode
}

output "id" {
  value = vault_config_group_policy_application.test.id
}

output "namespace" {
  value = vault_config_group_policy_application.test.namespace
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
  namespace                     = ""
}
```

### Administrative Namespace

When working with an administrative namespace, you can specify it either in the provider configuration or via the `VAULT_NAMESPACE` environment variable:

```hcl
provider "vault" {
  # Configuration can be read from environment variables:
  # VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE
  # Or specified directly:
  address   = "http://127.0.0.1:8200"
  token     = "your-token-here"
  namespace = "admin"
}

resource "vault_config_group_policy_application" "config" {
  group_policy_application_mode = "within_namespace_hierarchy"
  # namespace is inherited from provider configuration
}
```

Alternatively, using environment variables:

```bash
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="your-token-here"
export VAULT_NAMESPACE="admin"
```

```hcl
provider "vault" {
  # Configuration is read from environment variables
}

resource "vault_config_group_policy_application" "config" {
  group_policy_application_mode = "within_namespace_hierarchy"
}
```

## Argument Reference

The following arguments are supported:

* `group_policy_application_mode` - (Optional) Mode for group policy application. Must be either `within_namespace_hierarchy` or `any`. Defaults to `within_namespace_hierarchy`.
  - `within_namespace_hierarchy`: Policies only apply when the token authorizing a request was created in the same namespace as the group, or a descendant namespace.
  - `any`: Group policies apply to all members of a group, regardless of what namespace the request token came from.

* `namespace` - (Optional) Target namespace. Must be root (`""`) or administrative (`"admin"`) namespace. If omitted, the provider's configured namespace is used.
  Set this to `""` to explicitly target the root namespace. The value should not contain leading or trailing forward slashes.
  *Available only for Vault Enterprise*.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The resource ID (always `"config"`).

* `namespace` - The namespace where the configuration is managed.

## Import

The group policy application configuration can be imported using the ID `config`:

```
$ terraform import vault_config_group_policy_application.config config
```

## Behavior Notes

### Singleton Resource

This resource is a singleton, meaning only one instance can exist per Vault cluster. Multiple `vault_config_group_policy_application` resources in your Terraform configuration will conflict.

### Deletion Behavior

When this resource is destroyed via `terraform destroy`, it does not delete the configuration from Vault. Instead, it resets the mode to the default value `within_namespace_hierarchy`. This ensures that Vault always has a valid group policy application mode configured.

### Namespace Requirements

This resource can only be managed from:
- The root namespace (empty string `""`)
- The administrative namespace (`"admin"`)

Attempting to manage this resource from any other namespace will result in an error.

### Administrative Namespace

When using Vault with an administrative namespace configured (via `administrative_namespace_path` in the Vault server configuration), you can manage this resource from the admin namespace by setting `namespace = "admin"` or by configuring the provider's namespace.

Example Vault server configuration with administrative namespace:

```hcl
ui = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
disable_mlock = true

# Configure administrative namespace
administrative_namespace_path = "admin/"

listener "tcp" {
  address = "127.0.0.1:8200"
  cluster_address = "127.0.0.1:8201"
  tls_disable = 1
}

storage "raft" {
  path = "./vault-data/raft"
  node_id = "node1"
}
```

## Version Requirements

- Requires Vault Enterprise 1.13.8 or later
- This resource uses the Terraform Plugin Framework and is only available in provider versions that support it