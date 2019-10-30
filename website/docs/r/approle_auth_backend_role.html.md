---
layout: "vault"
page_title: "Vault: vault_approle_auth_backend_role resource"
sidebar_current: "docs-vault-resource-approle-auth-backend-role"
description: |-
  Manages AppRole auth backend roles in Vault.
---

# vault\_approle\_auth\_backend\_role

Manages an AppRole auth backend role in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/approle.html) for more
information.

## Example Usage

```hcl
resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "example" {
  backend        = vault_auth_backend.approle.path
  role_name      = "test-role"
  token_policies = ["default", "dev", "prod"]
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role.

* `role_id` - (Optional) The RoleID of this role. If not specified, one will be
  auto-generated.

* `bind_secret_id` - (Optional) Whether or not to require `secret_id` to be
  presented when logging in using this AppRole. Defaults to `true`.

* `secret_id_bound_cidrs` - (Optional) If set,
  specifies blocks of IP addresses which can perform the login operation.

* `secret_id_num_uses` - (Optional) The number of times any particular SecretID
  can be used to fetch a token from this AppRole, after which the SecretID will
  expire. A value of zero will allow unlimited uses.

* `secret_id_ttl` - (Optional) The number of seconds after which any SecretID
  expires.

* `backend` - (Optional) The unique name of the auth backend to configure.
  Defaults to `approle`.

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

### Deprecated Arguments

* `bound_cidr_list` - (Optional; Deprecated, use `secret_id_bound_cidrs` instead) If set,
  specifies blocks of IP addresses which can perform the login operation.

These arguments are deprecated since Vault 1.2 in favour of the common token arguments
documented above.

* `policies` - (Optional; Deprecated, use `token_policies` instead if you are running Vault >= 1.2) An array of strings
  specifying the policies to be set on tokens issued using this role.

* `period` - (Optional; Deprecated, use `token_period` instead if you are running Vault >= 1.2) If set, indicates that the
  token generated using this role should never expire. The token should be renewed within the
  duration specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. Specified in seconds.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

AppRole authentication backend roles can be imported using the `path`, e.g.

```
$ terraform import vault_approle_auth_backend_role.example auth/approle/role/test-role
```
