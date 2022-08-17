---
layout: "vault"
page_title: "Vault: vault_token_auth_backend_role resource"
sidebar_current: "docs-vault-resource-token-auth-backend-role"
description: |-
  Manages Token auth backend roles in Vault.
---

# vault\_token\_auth\_backend\_role

Manages Token auth backend role in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/token.html) for more
information.

## Example Usage

```hcl
resource "vault_token_auth_backend_role" "example" {
  role_name              = "my-role"
  allowed_policies       = ["dev", "test"]
  disallowed_policies    = ["default"]
  allowed_entity_aliases = ["test_entity"]
  orphan                 = true
  token_period           = "86400"
  renewable              = true
  token_explicit_max_ttl = "115200"
  path_suffix            = "path-suffix"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `role_name` - (Required) The name of the role.

* `allowed_policies` (Optional) List of allowed policies for given role.

* `allowed_policies_glob` (Optional) Set of allowed policies with glob match for given role.

* `disallowed_policies` (Optional) List of disallowed policies for given role.

* `disallowed_policies_glob` (Optional) Set of disallowed policies with glob match for given role.

* `allowed_entity_aliases` (Optional) List of allowed entity aliases.

* `orphan` (Optional) If true, tokens created against this policy will be orphan tokens.

* `renewable` (Optional) Whether to disable the ability of the token to be renewed past its initial TTL.

* `path_suffix` (Optional) Tokens created against this role will have the given suffix as part of their path in addition to the role name.

-> Due to a [bug](https://github.com/hashicorp/vault/issues/6296) with Vault, updating `path_suffix` or `bound_cidrs` to an empty string or list respectively will not actually update the value in Vault. Upgrade to Vault 1.1 and above to fix this, or [`taint`](https://www.terraform.io/docs/commands/taint.html) the resource. This *will* cause all existing tokens issued by this role to be revoked.

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

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks of IP
  addresses which can authenticate successfully, and ties the resulting token to these blocks
  as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an
  [explicit max TTL](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token in number of seconds. This is a hard cap even if `token_ttl` and
  `token_max_ttl` would otherwise allow a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on
  generated tokens; otherwise it will be added to the policies set in token_policies.

* `token_num_uses` - (Optional) The [maximum number](https://www.vaultproject.io/api-docs/token#token_num_uses)
   of times a generated token may be used (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Token auth backend roles can be imported with `auth/token/roles/` followed by the `role_name`, e.g.

```
$ terraform import vault_token_auth_backend_role.example auth/token/roles/my-role
```
