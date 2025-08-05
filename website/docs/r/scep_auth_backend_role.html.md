---
layout: "vault"
page_title: "Vault: vault_scep_auth_backend_role resource"
sidebar_current: "docs-vault-resource-scep-auth-backend-role"
description: |-
  Managing roles in an SCEP auth backend in Vault
---

# vault\_scep\_auth\_backend\_role

Provides a resource to create a role in an [SCEP auth backend within Vault](https://developer.hashicorp.com/vault/docs/auth/scep).

## Example Usage

```hcl
resource "vault_auth_backend" "scep" {
    path = "scep"
    type = "scep"
}

resource "vault_scep_auth_backend_role" "scep" {
    backend        = vault_auth_backend.scep.path
    name           = "scep_challenge"
    auth_type      = "static-challenge"
    challenge      = "well known secret"
    token_type     = "batch"
    token_ttl      = 300
    token_max_ttl  = 600
    token_policies = ["scep-clients"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Optional string: "scep") Path to the mounted SCEP auth backend.

* `name` - (Required string) Name of the role.

* `auth_type` - (Required string) The authentication type to use. This can be either "static-challenge" or "intune".

* `challenge` - (Optional) The static challenge to use if auth_type is "static-challenge", not used for other auth types.

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
  [explicit max TTL](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token in number of seconds. This is a hard cap even if `token_ttl` and
  `token_max_ttl` would otherwise allow a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on
  generated tokens; otherwise it will be added to the policies set in token_policies.

* `token_num_uses` - (Optional) The [maximum number](https://developer.hashicorp.com/vault/api-docs/auth/scep#token_num_uses)
   of times a generated token may be used (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

* `token_auth_metadata` - (Optional) The metadata to be tied to generated tokens.
  This should be a list or map containing the metadata in key value pairs.

For more details on the usage of each argument consult the [Vault SCEP API documentation](https://developer.hashicorp.com/vault/docs/auth/scep).

## Attribute Reference

No additional attributes are exposed by this resource.
