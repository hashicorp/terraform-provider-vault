---
layout: "vault"
page_title: "Vault: ephemeral vault_radius_auth_login resource"
sidebar_current: "docs-vault-ephemeral-radius-auth-login"
description: |-
  Login to Vault using RADIUS authentication and obtain ephemeral credentials

---

# vault_radius_auth_login (Ephemeral)

Provides an ephemeral resource to login with RADIUS authentication and obtain a Vault token.  
The token and authentication details are not stored in Terraform state and are automatically cleaned up by Vault when no longer needed.

This ephemeral resource authenticates a user via RADIUS and returns a Vault token that can be used for accessing Vault resources. The token is automatically revoked when the Terraform configuration is no longer active.

For more information, refer to
the [Vault RADIUS Auth documentation](https://developer.hashicorp.com/vault/docs/auth/radius).

## Example Usage

### Basic Usage

```hcl
resource "vault_auth_backend" "radius" {
  type = "radius"
  path = "radius"
}

resource "vault_radius_auth_backend" "radius" {
  mount             = vault_auth_backend.radius.path
  host              = "radius.example.com"
  port              = 1812
  secret_wo         = "my-radius-shared-secret"
  secret_wo_version = 1
}

ephemeral "vault_radius_auth_login" "test" {
  mount    = vault_auth_backend.radius.path
  username = "testuser"
  password = "testpass"
}

# Use the token from the login
output "token_accessor" {
  value     = ephemeral.vault_radius_auth_login.test.accessor
  sensitive = true
}

output "entity_id" {
  value = ephemeral.vault_radius_auth_login.test.entity_id
}
```

### With Custom Backend Path

```hcl
resource "vault_auth_backend" "custom" {
  type = "radius"
  path = "custom-radius"
}

resource "vault_radius_auth_backend" "custom" {
  mount             = vault_auth_backend.custom.path
  host              = "radius.company.com"
  port              = 1812
  secret_wo         = "shared-secret"
  secret_wo_version = 1
}

ephemeral "vault_radius_auth_login" "app" {
  mount    = vault_auth_backend.custom.path
  username = var.radius_username
  password = var.radius_password
}

# Access policies assigned to the authenticated user
output "assigned_policies" {
  value = ephemeral.vault_radius_auth_login.app.policies
}
```

### Using with Vault Provider Authentication

```hcl
resource "vault_auth_backend" "radius" {
  type = "radius"
  path = "radius"
}

resource "vault_radius_auth_backend" "radius" {
  mount             = vault_auth_backend.radius.path
  host              = "radius.example.com"
  port              = 1812
  secret_wo         = "shared-secret"
  secret_wo_version = 1
}

ephemeral "vault_radius_auth_login" "admin" {
  mount    = vault_auth_backend.radius.path
  username = "admin"
  password = var.admin_password
}

# Configure another Vault provider using the RADIUS-obtained token
provider "vault" {
  alias = "radius_authenticated"
  token = ephemeral.vault_radius_auth_login.admin.client_token
}

# Use the authenticated provider to manage resources
resource "vault_policy" "example" {
  provider = vault.radius_authenticated
  name     = "example-policy"
  policy   = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).

* `mount` - (Optional) The unique name of the RADIUS auth backend to login to. 
  Defaults to `radius`.

* `username` - (Required) The RADIUS username to authenticate with.

* `password` - (Required) The RADIUS password for the user. This field is marked as sensitive.

## Attribute Reference

In addition to the arguments above, the following attributes are exported:

* `client_token` - The Vault token generated from successful login. This field is marked as sensitive.

* `accessor` - The accessor for the token.

* `lease_duration` - The lease duration in seconds.

* `renewable` - Whether the token is renewable.

* `entity_id` - The entity ID of the authenticated user.

* `orphan` - Whether the token is an orphan.

* `mfa_requirement` - MFA requirement information, if applicable.

* `token_policies` - List of token policies attached to the token.

* `identity_policies` - List of identity policies attached to the token.

* `policies` - List of all policies (token + identity) attached to the token.

* `metadata` - Map of metadata associated with the authentication, such as username and policy information.

## Ephemeral Resource Behavior

This is an ephemeral resource, which means:

- The authentication token and credentials are **not** stored in the Terraform state file
- The token is automatically revoked when it's no longer needed by Terraform
- Each run that uses this resource will perform a new RADIUS authentication
- The resource follows Terraform's standard lifecycle for ephemeral resources

## Security Considerations

- Store passwords in secure variables (marked as sensitive) rather than hardcoding them in configuration files
- Use environment variables or secure secret management tools for sensitive credentials
- The `client_token` is marked as sensitive and will not be displayed in logs or console output
- Consider using time-limited tokens with appropriate lease durations for production use
- Ensure RADIUS shared secrets are rotated regularly

## Required Vault Capabilities

The Vault token used to configure the provider must have the following capabilities:

- `read` on `auth/<mount>/login/<username>` to perform authentication
