---
layout: "vault"
page_title: "Vault: vault_alicloud_auth_backend_role resource"
sidebar_current: "docs-vault-resource-alicloud-auth-backend-role"
description: |-
  Managing roles in an AliCloud auth backend in Vault
---

# vault\_alicloud\_auth\_backend\_role

Provides a resource to create a role in an [AliCloud auth backend within Vault](https://www.vaultproject.io/docs/auth/alicloud.html).

## Example Usage

```hcl
resource "vault_auth_backend" "alicloud" {
    type = "alicloud"
    path = "alicloud"
}

resource "vault_alicloud_auth_backend_role" "alicloud" {
    backend = vault_auth_backend.alicloud.path
    role    = "example"
    arn     = "acs:ram:123456:tf:role/foobar"

}
```

## Argument Reference

The following arguments are supported:

* `role` - (Required; Forces new resource) Name of the role. Must correspond with the name of
  the role reflected in the arn.

* `arn` - (Required) The role's arn.

* `backend` - (Optional; Forces new resource) Path to the mounted AliCloud auth backend.
  Defaults to `alicloud`

For more details on the usage of each argument consult the [Vault AliCloud API documentation](https://www.vaultproject.io/api/auth/alicloud/index.html).

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

## Attribute Reference

No additional attributes are exposed by this resource.

## Import

Alicloud authentication roles can be imported using the `path`, e.g.

```
$ terraform import vault_alicloud_auth_backend_role.my_role auth/alicloud/role/my_role
```
