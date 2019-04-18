---
layout: "vault"
page_title: "Vault: vault_jwt_auth_backend_role resource"
sidebar_current: "docs-vault-resource-jwt-auth-backend-role"
description: |-
  Manages JWT/OIDC auth backend roles in Vault.
---

# vault\_jwt\_auth\_backend\_role

Manages an JWT/OIDC auth backend role in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/jwt.html) for more
information.

## Example Usage

Role for JWT backend:

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
  role_type = "jwt"
}
```

Role for OIDC backend:

```hcl
resource "vault_jwt_auth_backend" "oidc" {
  path = "oidc"
  default_role = "test-role"
}

resource "vault_jwt_auth_backend_role" "example" {
  backend   = "${vault_jwt_auth_backend.oidc.path}"
  role_name = "test-role"
  policies  = ["default", "dev", "prod"]

  bound_audiences = ["https://myco.test"]
  user_claim      = "https://vault/user"
  allowed_redirect_uris = ["http://localhost:8200/ui/vault/auth/oidc/oidc/callback"]
  role_type = "oidc"
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role.

* `role_type` - (Optional) Type of role, either "oidc" (default) or "jwt".

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

* `groups_claim_delimiter_pattern` - (Optional; Deprecated. This field has been
  removed since Vault 1.1. If the groups claim is not at the top level, it can
  now be specified as a [JSONPointer](https://tools.ietf.org/html/rfc6901).)
  A pattern of delimiters
  used to allow the groups_claim to live outside of the top-level JWT structure.
  For instance, a groups_claim of meta/user.name/groups with this field
  set to // will expect nested structures named meta, user.name, and groups.
  If this field was set to /./ the groups information would expect to be
  via nested structures of meta, user, name, and groups.

* `backend` - (Optional) The unique name of the auth backend to configure.
  Defaults to `jwt`.

* `allowed_redirect_uris` - (Optional) The list of allowed values for redirect_uri during OIDC logins.
  Required for OIDC roles

## Attributes Reference

No additional attributes are exported by this resource.

## Import

JWT authentication backend roles can be imported using the `path`, e.g.

```
$ terraform import vault_jwt_auth_backend_role.example auth/jwt/role/test-role
```
