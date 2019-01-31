---
layout: "vault"
page_title: "Vault: vault_jwt_auth_backend_role resource"
sidebar_current: "docs-vault-jwt-auth-backend-role"
description: |-
  Manages JWT auth backend roles in Vault.
---

# vault\_jwt\_auth\_backend\_role

Manages an JWT auth backend role in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/jwt.html) for more
information.

## Example Usage

```hcl
resource "vault_jwt_auth_backend" "jwt" {
  path = "jwt"
}

resource "vault_jwt_auth_backend_role" "example" {
  backend   = "${vault_jwt_auth_backend.jwt.path}"
  role_name = "test-role"
  policies  = ["default", "dev", "prod"]

  bound_audiences = ["https://myco.test"]
  user_claim      = "https://vault/user"
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role.

* `bound_audiences` - (Required) List of `aud` claims to match
  against. Any match is sufficient.

* `user_claim` - (Required) The claim to use to uniquely identify
  the user; this will be used as the name for the Identity entity alias created
  due to a successful login.

* `policies` - (Optional) Policies to be set on tokens issued using this role.

* `ttl` - (Optional) The initial/renewal TTL of tokens issued using this role,
  in seconds.

* `max_ttl` - (Optional) The maximum allowed lifetime of tokens issued using
  this role, in seconds.

* `period` - (Optional) If set, indicates that the token generated
  using this role should never expire, but instead always use the value set
  here as the TTL for every renewal. 

* `num_uses` - (Optional) If set, puts a use-count limitation on the issued
  token.

* `bound_subject` - (Optional) If set, requires that the `sub` claim matches
  this value.

* `bound_cidrs` - (Optional) If set, a list of CIDRs valid as the source 
  address for login requests. This value is also encoded into any resulting
  token.

* `groups_claim` - (Optional) The claim to use to uniquely identify
  the set of groups to which the user belongs; this will be used as the names
  for the Identity group aliases created due to a successful login. The claim
  value must be a list of strings.

* `backend` - (Optional) The unique name of the auth backend to configure.
  Defaults to `jwt`.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

JWT authentication backend roles can be imported using the `path`, e.g.

```
$ terraform import vault_jwt_auth_backend_role.example auth/jwt/role/test-role
```
