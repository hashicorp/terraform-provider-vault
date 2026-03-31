---
layout: "vault"
page_title: "Vault: vault_userpass_auth_backend_user resource"
sidebar_current: "docs-vault-resource-userpass-auth-backend-user"
description: |-
  Manages users for the Userpass auth backend in Vault.
---

# vault_userpass_auth_backend_user

Manages a user for the [Userpass auth method](https://developer.hashicorp.com/vault/docs/auth/userpass) in Vault.

## Example Usage

### Password-Based User With Token Settings

```hcl
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

resource "vault_userpass_auth_backend_user" "user" {
  mount       = vault_auth_backend.userpass.path
  username    = "example-user"
  password_wo = "initial-password"

  token_policies = ["default", "dev"]
  token_ttl      = 3600
  token_max_ttl  = 7200
  token_num_uses = 0
  token_period   = 0
  token_no_default_policy = false
}
```

### Bcrypt Password Hash User

```hcl
resource "vault_userpass_auth_backend_user" "user_with_hash" {
  mount         = vault_auth_backend.userpass.path
  username      = "example-user-hash"
  password_hash = "$2a$10$V1HAj0oLIhJtqkj3w0zGx.fjMxmVnY2m0sI4GTiD6W69eCi7epTzW"

  token_policies = ["default", "dev"]
  token_ttl      = 3600
  token_max_ttl  = 7200
}
```

### Namespaced User (Vault Enterprise)

```hcl
resource "vault_namespace" "test" {
  path = "ns-team-a"
}

resource "vault_auth_backend" "userpass_ns" {
  type      = "userpass"
  path      = "userpass-ns"
  namespace = vault_namespace.test.path
}

resource "vault_userpass_auth_backend_user" "user_namespaced" {
  namespace   = vault_namespace.test.path
  mount       = vault_auth_backend.userpass_ns.path
  username    = "example-user-ns"
  password_wo = "initial-password"
}
```

### Invalid Configuration Examples (Do Not Apply)

```hcl
# Invalid: both password_wo and password_hash are set.
# Exactly one of these fields must be provided.
# resource "vault_userpass_auth_backend_user" "invalid_both" {
#   mount         = vault_auth_backend.userpass.path
#   username      = "invalid-both"
#   password_wo   = "plain-password"
#   password_hash = "$2a$10$7EqJtq98hPqEX7fNZaFWoOHiW6m7jzF3sQ6Y8bK1J0Y9mXw1lK5W2"
# }

# Invalid: password_hash must be a valid bcrypt hash.
# resource "vault_userpass_auth_backend_user" "invalid_hash" {
#   mount         = vault_auth_backend.userpass.path
#   username      = "invalid-hash"
#   password_hash = "not-bcrypt"
# }
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Mount path for the Userpass auth engine in Vault.

* `username` - (Required) Username for this Userpass user.

* `password_wo` - (Optional, Sensitive, Write-only) Password for this user.
  This value is never read back from Vault or stored in Terraform state.

* `password_hash` - (Optional, Sensitive, Write-only) Pre-hashed password for this user in bcrypt format.
  Mutually exclusive with `password_wo`. Available in Vault 1.17 and later.

Exactly one of `password_wo` or `password_hash` must be specified.


### Token Settings

For more information on token settings, see the [Token Fields documentation](/docs/providers/vault/index.html#token-fields).

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in seconds. 
  Its current value will be referenced at renewal time.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in seconds. 
  Its current value will be referenced at renewal time.

* `token_period` - (Optional) The maximum allowed period value when a periodic token is requested from this role.

* `token_policies` - (Optional) List of policies to encode onto generated tokens. Depending 
  on the auth method, this list may be supplemented by user/group/other values.

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks of IP 
  addresses which can authenticate successfully, and ties the resulting token to these blocks 
  as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an explicit max TTL onto the token 
  in seconds. This is a hard cap even if `token_ttl` and `token_max_ttl` would otherwise allow 
  a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on 
  generated tokens; otherwise it will be added to the policies set in `token_policies`.

* `token_num_uses` - (Optional) The maximum number of times a generated token may be used 
  (within its lifetime); 0 means unlimited. If you require the token to have the ability to 
  create child tokens, you will need to set this value to 0.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

* `alias_metadata` - (Optional) A map of string to string that will be set as metadata on
  the identity alias. **Note:** This field is only supported in Vault Enterprise 1.21.0 and above.
  If configured for vault ent version lesser than 1.21.0, this field will be ignored, even though the value is persisted in the state file.
  *Available only for Vault Enterprise*.

## Import

Userpass auth backend users can be imported using the path, e.g.

```shell
$ terraform import vault_userpass_auth_backend_user.user auth/userpass/users/example-user
```