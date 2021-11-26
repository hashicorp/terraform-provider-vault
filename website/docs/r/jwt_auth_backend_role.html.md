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
  backend         = vault_jwt_auth_backend.jwt.path
  role_name       = "test-role"
  token_policies  = ["default", "dev", "prod"]

  bound_audiences = ["https://myco.test"]
  bound_claims = {
    color = "red,green,blue"
  }
  user_claim      = "https://vault/user"
  role_type       = "jwt"
}
```

Role for OIDC backend:

```hcl
resource "vault_jwt_auth_backend" "oidc" {
  path = "oidc"
  default_role = "test-role"
}

resource "vault_jwt_auth_backend_role" "example" {
  backend         = vault_jwt_auth_backend.oidc.path
  role_name       = "test-role"
  token_policies  = ["default", "dev", "prod"]

  user_claim            = "https://vault/user"
  role_type             = "oidc"
  allowed_redirect_uris = ["http://localhost:8200/ui/vault/auth/oidc/oidc/callback"]
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role.

* `role_type` - (Optional) Type of role, either "oidc" (default) or "jwt".

* `bound_audiences` - (Required for roles of type `jwt`, optional for roles of
  type `oidc`) List of `aud` claims to match against. Any match is sufficient.

* `user_claim` - (Required) The claim to use to uniquely identify
  the user; this will be used as the name for the Identity entity alias created
  due to a successful login.

* `bound_subject` - (Optional) If set, requires that the `sub` claim matches
  this value.

* `bound_claims` - (Optional) If set, a map of claims to values to match against.
  A claim's value must be a string, which may contain one value or multiple
  comma-separated values, e.g. `"red"` or `"red,green,blue"`.

* `bound_claims_type` - (Optional) How to interpret values in the claims/values
  map (`bound_claims`): can be either `string` (exact match) or `glob` (wildcard
  match). Requires Vault 1.4.0 or above.

* `claim_mappings` - (Optional) If set, a map of claims (keys) to be copied
  to specified metadata fields (values).

* `oidc_scopes` - (Optional) If set, a list of OIDC scopes to be used with an OIDC role.
  The standard scope "openid" is automatically included and need not be specified.

* `groups_claim` - (Optional) The claim to use to uniquely identify
  the set of groups to which the user belongs; this will be used as the names
  for the Identity group aliases created due to a successful login. The claim
  value must be a list of strings.

* `backend` - (Optional) The unique name of the auth backend to configure.
  Defaults to `jwt`.

* `allowed_redirect_uris` - (Optional) The list of allowed values for redirect_uri during OIDC logins.
  Required for OIDC roles

* `clock_skew_leeway` - (Optional) The amount of leeway to add to all claims to account for clock skew, in
  seconds. Defaults to `60` seconds if set to `0` and can be disabled if set to `-1`.
  Only applicable with "jwt" roles.

* `expiration_leeway` - (Optional) The amount of leeway to add to expiration (`exp`) claims to account for
  clock skew, in seconds. Defaults to `60` seconds if set to `0` and can be disabled if set to `-1`.
  Only applicable with "jwt" roles.

* `not_before_leeway` - (Optional) The amount of leeway to add to not before (`nbf`) claims to account for
  clock skew, in seconds. Defaults to `60` seconds if set to `0` and can be disabled if set to `-1`.
  Only applicable with "jwt" roles.

* `verbose_oidc_logging` - (Optional) Log received OIDC tokens and claims when debug-level
  logging is active. Not recommended in production since sensitive information may be present
  in OIDC responses.

### Common Token Arguments

These arguments are common across several Authentication Token resources since Vault 1.2.

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_period` - (Optional) If set, indicates that the
  token generated using this role should never expire. The token should be renewed within the
  duration specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. Specified in seconds.

* `token_policies` - (Optional) List of policies to encode onto generated tokens. Depending
  on the auth method, this list may be supplemented by user/group/other values.

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks of IP
  addresses which can authenticate successfully, and ties the resulting token to these blocks
  as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an
  [explicit max TTL](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token in number of seconds. This is a hard cap even if `token_ttl` and
  `token_max_ttl` would otherwise allow a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on
  generated tokens; otherwise it will be added to the policies set in token_policies.

* `token_num_uses` - (Optional) The
  [period](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls),
  if any, in number of seconds to set on the token.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

JWT authentication backend roles can be imported using the `path`, e.g.

```
$ terraform import vault_jwt_auth_backend_role.example auth/jwt/role/test-role
```
