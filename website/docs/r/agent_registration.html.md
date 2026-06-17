---
layout: "vault"
page_title: "Vault: vault_agent_registration resource"
sidebar_current: "docs-vault-resource-sys-agent-registration"
description: |-
  Manages Agent Registry records in Vault Enterprise.
---

# vault\_agent\_registration

~> **Beta feature:** This feature is currently available as a preview and is possibly incomplete and subject to change. **We strongly discourage using preview or beta features with production workflows.**

Manages Agent Registry records in Vault Enterprise. An Agent Registry record allows you to register Vault agents with specific identity entities and configure ceiling policies that limit the maximum permissions an agent can obtain.

~> **Important** This resource is available only in Vault Enterprise and requires Vault 2.0.3 or later.

### Relationship to OAuth Resource Server 

These two features work together. You may want to refer to [OAuth Resource Server Terraform Resource](oauth_resource_server_config_profile.html.md).

### Basic Agent Registry Record

```hcl
resource "vault_identity_entity" "agent" {
  name     = "my-agent-entity"
  policies = ["default"]
}

resource "vault_agent_registration" "example" {
  display_name = "my-agent"
  entity_id    = vault_identity_entity.agent.id
}
```

### Agent Registry Record with Ceiling Policies

```hcl
resource "vault_policy" "agent_ceiling" {
  name = "agent-ceiling-policy"
  policy = <<EOT
path "secret/data/*" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOT
}

resource "vault_identity_entity" "agent" {
  name     = "my-agent-entity"
  policies = ["default"]
}

resource "vault_agent_registration" "example" {
  display_name     = "my-agent"
  entity_id        = vault_identity_entity.agent.id
  ceiling_policies = [vault_policy.agent_ceiling.name]
  description      = "Production agent for application X"
}
```

### Agent Registry Record Without Default Ceiling Policy

```hcl
resource "vault_identity_entity" "agent" {
  name = "my-agent-entity"
}

resource "vault_agent_registration" "example" {
  display_name              = "my-agent"
  entity_id                 = vault_identity_entity.agent.id
  no_default_ceiling_policy = true
}
```

### Agent Registry Record in a Namespace

```hcl
resource "vault_namespace" "app" {
  path = "application"
}

resource "vault_identity_entity" "agent" {
  namespace = vault_namespace.app.path
  name      = "my-agent-entity"
  policies  = ["default"]
}

resource "vault_agent_registration" "example" {
  namespace    = vault_namespace.app.path
  display_name = "my-agent"
  entity_id    = vault_identity_entity.agent.id
}
```

### Agent Registry Record with Multiple Ceiling Policies

```hcl
resource "vault_policy" "secrets_read" {
  name = "secrets-read"
  policy = <<EOT
path "secret/data/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "auth_renew" {
  name = "auth-renew"
  policy = <<EOT
path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOT
}

resource "vault_identity_entity" "agent" {
  name     = "my-agent-entity"
  policies = ["default"]
}

resource "vault_agent_registration" "example" {
  display_name = "my-agent"
  entity_id    = vault_identity_entity.agent.id
  ceiling_policies = [
    vault_policy.secrets_read.name,
    vault_policy.auth_renew.name,
  ]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).

* `display_name` - (Required) The display name for the Agent Registry record. This field must be unique per Vault namespace. Within Terraform, this is used as the unique identifier for the agent. Changing this on an existing resource will force the resource to be deleted from Vault and a new resource to be created in Vault.

* `entity_id` - (Required) The ID of the identity entity to associate with this Agent Registry record. The entity must exist before you create the Agent Registry record.

* `ceiling_policies` - (Optional) A list of policy names that define the maximum permissions this agent can obtain. These policies act as a ceiling - the agent cannot obtain permissions beyond what these policies allow, even if the entity or token policies would grant more permissions. By default, Vault applies a default ceiling policy unless `no_default_ceiling_policy` is set to `true`.

* `no_default_ceiling_policy` - (Optional) When set to `true`, prevents Vault from applying the default ceiling policy to this agent. This allows you to have complete control over the agent's ceiling policies. Defaults to `false`.

* `description` - (Optional) A human-readable description of the Agent Registry record. This field is for documentation purposes and does not affect the agent's behavior.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The unique identifier for the Agent Registry record. This is a GUID-like identifier automatically generated by Vault.

* `creation_time` - The timestamp when the Agent Registry record was created, in RFC3339 format.

* `last_updated_time` - The timestamp when the Agent Registry record was last updated, in RFC3339 format.

## Import

You can import Agent Registry records using either their `display_name` or their
`id` (UUID). The provider auto-detects which you supplied: if the import string
parses as a UUID, the provider reads the record by `id`; otherwise it reads the
record by `display_name`.

```
$ terraform import vault_agent_registration.example my-agent
```

To import a record by `id`:

```
$ terraform import vault_agent_registration.example 550e8400-e29b-41d4-a716-446655440000
```

The import string does not encode the namespace. To import a record from a
namespace, set the `TERRAFORM_VAULT_NAMESPACE_IMPORT` environment variable:

```
$ TERRAFORM_VAULT_NAMESPACE_IMPORT=application terraform import vault_agent_registration.example my-agent
```

## Notes

* **Mount:** The Agent Registry is mounted by default. There is no need to take action to enable it.

* **Ceiling Policies**: Ceiling policies define the maximum permissions an agent can obtain. Even if the associated entity or token policies grant broader permissions, the agent will be limited to the intersection of all applicable policies and the ceiling policies.

* **Default Ceiling Policy**: By default, Vault applies a default ceiling policy to Agent Registry records. This policy is automatically filtered out when reading the resource state, so only user-specified ceiling policies appear in the `ceiling_policies` attribute.

* **Entity Requirement**: The identity entity specified in `entity_id` must exist before you create the Agent Registry record. The entity defines the base identity for the agent.

* **Display Name Uniqueness**: The `display_name` must be unique within the namespace. Attempting to create multiple Agent Registry records with the same display name will result in an error.

* **Immutable Display Name**: Changing the `display_name` requires destroying and recreating the Agent Registry record, as it serves as the unique identifier.

* **Enterprise Feature**: Agent Registry records are only available in Vault Enterprise. Attempting to use this resource with Vault Community Edition will result in an error.

* **Version Requirement**: This resource requires Vault 2.0.1 or later.
