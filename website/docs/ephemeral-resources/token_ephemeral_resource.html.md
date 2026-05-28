---
layout: "vault"
page_title: "Vault: ephemeral vault_token resource"
sidebar_current: "docs-vault-ephemeral-token"
description: |-
  Create ephemeral Vault tokens with automatic revocation

---

# vault_token (Ephemeral)

Creates ephemeral Vault tokens that are not stored in Terraform state and are automatically revoked when no longer needed.

This ephemeral resource provides a secure way to generate Vault tokens for use within Terraform configurations. The tokens are automatically revoked when the Terraform run completes, ensuring proper cleanup and security.

~> **Important** Ephemeral resources are designed for sensitive data that should not be stored in Terraform state. However, the data will still appear in console output when Terraform runs and may be included in plan files if secrets are interpolated into resource attributes. Protect these artifacts accordingly.

For more information, refer to the [Vault Token documentation](https://developer.hashicorp.com/vault/docs/concepts/tokens).

## Example Usage

### Basic Token Creation

```hcl
ephemeral "vault_token" "example" {
  policies = ["default", "app-policy"]
  ttl      = "1h"
}

# Use the token in a provider configuration
provider "vault" {
  alias   = "app"
  address = "https://vault.example.com"
  token   = ephemeral.vault_token.example.client_token
}
```

### Token with Role

```hcl
resource "vault_token_auth_backend_role" "app_role" {
  role_name              = "app-role"
  allowed_policies       = ["app-policy"]
  orphan                 = true
  token_period           = "86400"
  renewable              = true
  token_explicit_max_ttl = "115200"
}

ephemeral "vault_token" "app_token" {
  role_name = vault_token_auth_backend_role.app_role.role_name
  ttl       = "24h"
  renewable = true
  
  # Defer ephemeral resource evaluation until the role is created
  mount_id = vault_token_auth_backend_role.app_role.id
}
```

### Batch Token

```hcl
ephemeral "vault_token" "batch" {
  type     = "batch"
  policies = ["read-only"]
  ttl      = "30m"
}
```

### Wrapped Token

```hcl
ephemeral "vault_token" "wrapped" {
  policies     = ["app-policy"]
  ttl          = "1h"
  wrapping_ttl = "5m"
}
```

### Orphan Token with Metadata

```hcl
ephemeral "vault_token" "orphan" {
  no_parent = true
  policies  = ["app-policy"]
  ttl       = "2h"
  
  metadata = {
    application = "my-app"
    environment = "production"
    owner       = "platform-team"
  }
  
  display_name = "app-production-token"
}
```

### Periodic Token

```hcl
ephemeral "vault_token" "periodic" {
  policies  = ["app-policy"]
  period    = "24h"
  renewable = true
}
```

### Token with Entity Alias

```hcl
# Create an auth backend (e.g., userpass) to associate the entity alias with
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

resource "vault_identity_entity" "app" {
  name     = "app-entity"
  policies = ["app-policy"]
}

# Entity alias must be associated with a non-token auth backend
resource "vault_identity_entity_alias" "app_alias" {
  name           = "app-user"
  mount_accessor = vault_auth_backend.userpass.accessor
  canonical_id   = vault_identity_entity.app.id
}

# Token role must allow the entity alias
resource "vault_token_auth_backend_role" "app_role" {
  role_name              = "app-role"
  allowed_policies       = ["app-policy"]
  allowed_entity_aliases = [vault_identity_entity_alias.app_alias.name]
}

ephemeral "vault_token" "with_entity" {
  role_name    = vault_token_auth_backend_role.app_role.role_name
  entity_alias = vault_identity_entity_alias.app_alias.name
  ttl          = "1h"
  
  # Defer ephemeral resource evaluation until dependencies are created
  mount_id = vault_identity_entity_alias.app_alias.id
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `id` - (Optional) The ID of the client token. This is an input field, not a resource identifier. Can only be specified by a root token. The ID provided may not contain a '.' character and should not start with the 's.' prefix.

* `role_name` - (Optional) The token role name. When specified, the token is created using the specified role's configuration.

* `policies` - (Optional) List of policies to attach to the token.

* `no_parent` - (Optional) Flag to create a token without parent. Creates an orphan token that is not a child of the token used to create it.

* `no_default_policy` - (Optional) Flag to disable the default policy. If true, the default policy will not be attached to the token.

* `renewable` - (Optional) Flag to allow the token to be renewed. Defaults to true for service tokens.

* `ttl` - (Optional) The TTL period of the token. Examples: "1h", "30m", "3600s". If not specified, uses Vault's default TTL.

* `explicit_max_ttl` - (Optional) The explicit max TTL of the token. This is the maximum time the token can exist, regardless of renewals.

* `display_name` - (Optional) The display name of the token. Defaults to "token".

* `num_uses` - (Optional) The number of allowed uses of the token. After this many uses, the token will automatically be revoked. A value of 0 means unlimited uses.

* `period` - (Optional) The period of the token for periodic tokens. If set, the token will be renewed indefinitely as long as it is renewed within this period. Examples: "24h", "1h30m".

* `metadata` - (Optional) Metadata to be associated with the token. This is a map of string key-value pairs.

* `type` - (Optional) The token type. Can be 'batch' or 'service'. Defaults to 'service'. Batch tokens are lightweight and cannot be renewed, while service tokens are the standard token type.

* `entity_alias` - (Optional) Name of the entity alias to associate with during token creation. This links the token to an existing identity entity.

* `wrapping_ttl` - (Optional) The TTL period of the wrapped token. If set, the token will be response-wrapped. Examples: "5m", "300s".

* `mount_id` - (Optional) If value is set, will defer provisioning the ephemeral resource until
  `terraform apply`. For more details, please refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

## Required Vault Capabilities

Use of this resource requires the following capabilities:

* `create` and `update` on `auth/token/create` or `auth/token/create/<role_name>` if using a role
* `update` on `auth/token/revoke-accessor` for automatic token revocation during cleanup

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `client_token` - The client token value. Only populated for non-wrapped tokens.

* `wrapped_token` - The wrapped token value. Only populated when `wrapping_ttl` is set.

* `wrapping_accessor` - The wrapping accessor. Only populated when `wrapping_ttl` is set.

* `lease_duration` - The token lease duration in seconds.

* `lease_id` - The lease ID associated with the token.

* `accessor` - The token accessor. This is a unique identifier for the token that can be used for token operations without exposing the token itself.

* `token_policies` - The list of policies attached to the token.

* `entity_id` - The entity ID associated with the token.

* `orphan` - Whether the token is an orphan token.

## Token Types

### Service Tokens

Service tokens are the default token type. They:
- Can be renewed
- Have an accessor
- Are tracked in Vault's token store
- Can be revoked via API
- Support all token features

### Batch Tokens

Batch tokens are lightweight tokens that:
- Cannot be renewed
- Do not have an accessor (for wrapped batch tokens)
- Are not tracked in Vault's token store
- Cannot be revoked via API (they expire naturally)
- Have limited functionality but better performance

**Batch Token Restrictions:**
Batch tokens cannot use the following parameters:
- `num_uses` - Error: "batch tokens cannot have 'num_uses' set"
- `period` - Error: "batch tokens cannot have 'period' set"
- `explicit_max_ttl` - Error: "batch tokens cannot have 'explicit_max_ttl' set"

When using batch tokens with roles, the role must be configured with:
- `token_type = "batch"`
- `orphan = true`
- `renewable = false`

## Automatic Revocation

This ephemeral resource automatically revokes tokens when they are no longer needed:

- **Service tokens**: Revoked using the token accessor via the `auth/token/revoke-accessor` endpoint
- **Batch tokens**: Cannot be revoked via API; they expire naturally based on their TTL
- **Wrapped tokens**: The wrapped token accessor is used for revocation if available

If revocation fails (e.g., due to network issues), a warning is logged, but the operation continues. The token will still expire based on its TTL.

## Notes

* Tokens created with this resource are ephemeral and will be automatically revoked when the Terraform run completes.
* Batch tokens cannot be renewed or revoked via API - they expire based on their TTL.
* Wrapped tokens provide an additional layer of security by requiring unwrapping before use.
* Orphan tokens (created with `no_parent = true`) are not revoked when their parent token is revoked.
* Periodic tokens can be renewed indefinitely as long as they are renewed within the period.