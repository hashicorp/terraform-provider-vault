---
layout: "vault"
page_title: "Vault: vault_github_auth_backend resource"
sidebar_current: "docs-vault-github-auth-backend"
description: |-
  Manages Github Auth mounts in Vault.
---

# vault\_github\_auth\_backend

Manages a Github Auth mount in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/github.html) for more
information.

## Example Usage

```hcl
resource "vault_github_auth_backend" "example" {
  organization = "myorg"
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Optional) Path where the auth backend is mounted. Defaults to `auth/github`
  if not specified.

* `organization` - (Required) The organization configured users must be part of.

* `base_url` - (Optional) The API endpoint to use. Useful if you
  are running GitHub Enterprise or an API-compatible authentication server.

* `description` - (Optional) Specifies the description of the mount.
  This overrides the current stored value, if any.

The `tune` block is used to tune the auth backend:

* `default_lease_ttl` - (Optional) Specifies the default time-to-live.
  If set, this overrides the global default.
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `max_lease_ttl` - (Optional) Specifies the maximum time-to-live.
  If set, this overrides the global default.
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `audit_non_hmac_response_keys` - (Optional) Specifies the list of keys that will
  not be HMAC'd by audit devices in the response data object.

* `audit_non_hmac_request_keys` - (Optional) Specifies the list of keys that will
  not be HMAC'd by audit devices in the request data object.

* `listing_visibility` - (Optional) Specifies whether to show this mount in
  the UI-specific listing endpoint. Valid values are "unauth" or "hidden".

* `passthrough_request_headers` - (Optional) List of headers to whitelist and
  pass from the request to the backend.

* `allowed_response_headers` - (Optional) List of headers to whitelist and allowing
  a plugin to include them in the response.

* `token_type` - (Optional) Specifies the type of tokens that should be returned by
  the mount. Valid values are "default-service", "default-batch", "service", "batch".

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `accessor` - The mount accessor related to the auth mount. It is useful for integration with [Identity Secrets Engine](https://www.vaultproject.io/docs/secrets/identity/index.html).

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

* `token_num_uses` - (Optional) The number of times issued tokens can be used.
  A value of 0 means unlimited uses.

* `token_num_uses` - (Optional) The
  [period](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls),
  if any, in number of seconds to set on the token.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

### Deprecated Arguments

These arguments are deprecated since Vault 1.2 in favour of the common token arguments
documented above.

* `ttl` - (Optional; Deprecated, use `token_ttl` instead if you are running Vault >= 1.2) The TTL period of tokens issued
  using this role. This must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration).

* `max_ttl` - (Optional; Deprecated, use `token_max_ttl` instead if you are running Vault >= 1.2) The maximum allowed lifetime of tokens
  issued using this role. This must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration).

## Import

Github authentication mounts can be imported using the `path`, e.g.

```
$ terraform import vault_github_auth_backend.example github
```
