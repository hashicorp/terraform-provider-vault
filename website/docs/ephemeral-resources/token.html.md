---
layout: "vault"
page_title: "Vault: ephemeral vault_token resource"
sidebar_current: "docs-vault-ephemeral-token"
description: |-
  Create ephemeral Vault tokens that are not stored in Terraform state.

---

# vault\_token (Ephemeral)

Creates an ephemeral Vault token. The token is not stored in Terraform state and will persist
until its TTL or period expires.

This is the ephemeral equivalent of the [vault_token](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/token) resource. It supports all the same token
creation options but produces a token that never touches the state file, making it ideal for
passing short-lived or periodic tokens to other systems.

The token used by Terraform will require the following permissions in Vault:

```hcl
path "auth/token/create" {
  capabilities = ["create", "update"]
}
```

If using `role_name`, the permission path changes to:

```hcl
path "auth/token/create/<role_name>" {
  capabilities = ["create", "update"]
}
```

For more information, refer to the
[Vault Token Auth Method documentation](https://developer.hashicorp.com/vault/docs/auth/token).

## Example Usage

### Basic Usage

```hcl
resource "vault_policy" "example" {
  name   = "nomad-server"
  policy = <<EOT
path "secret/*" { capabilities = ["read"] }
EOT
}

ephemeral "vault_token" "example" {
  policies = [vault_policy.example.name]
  ttl      = "24h"
}
```

### Periodic Orphan Token

```hcl
ephemeral "vault_token" "nomad" {
  policies  = [vault_policy.nomad.name]
  period    = "72h"
  no_parent = true
}
```

### With Token Role

```hcl
resource "vault_token_auth_backend_role" "example" {
  role_name        = "app-role"
  allowed_policies = ["default", "app"]
  orphan           = true
  token_period     = 86400
}

ephemeral "vault_token" "example" {
  role_name = vault_token_auth_backend_role.example.role_name
}
```

### Wrapped Token

```hcl
ephemeral "vault_token" "example" {
  policies     = ["app"]
  ttl          = "1h"
  wrapping_ttl = "5m"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount_id` - (Optional) If value is set, will defer provisioning the ephemeral resource until
  `terraform apply`. For more details, please refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

* `role_name` - (Optional) The token role name.

* `policies` - (Optional) List of policies to attach to this token.

* `no_parent` - (Optional) Flag to create a token without parent (orphan token).

* `no_default_policy` - (Optional) Flag to not attach the default policy to this token.

* `renewable` - (Optional) Flag to allow the token to be renewed.

* `ttl` - (Optional) The TTL period of the token. This is specified as a numeric string with suffix like `"30s"` or `"5m"`.

* `explicit_max_ttl` - (Optional) The explicit max TTL of the token. This is specified as a numeric string with suffix like `"30s"` or `"5m"`.

* `period` - (Optional) The period of the token. This is specified as a numeric string with suffix like `"30s"` or `"5m"`.

* `display_name` - (Optional) String containing the token display name.

* `num_uses` - (Optional) The number of allowed uses of the token.

* `wrapping_ttl` - (Optional) The TTL period of the wrapped token.

* `metadata` - (Optional) Metadata to be associated with the token.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `client_token` - The client token. This value is sensitive and ephemeral — it is not stored in Terraform state.

* `wrapped_token` - The client wrapped token. Only set when `wrapping_ttl` is configured. This value is sensitive.

* `wrapping_accessor` - The client wrapping accessor. Only set when `wrapping_ttl` is configured. This value is sensitive.

* `lease_duration` - The token lease duration in seconds.

* `lease_started` - The time the token lease started, in RFC3339 format.
