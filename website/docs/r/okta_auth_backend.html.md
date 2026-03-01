---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-okta-auth-backend"
description: |-
  Managing Okta auth backends in Vault
---

# vault\_okta\_auth\_backend

Provides a resource for managing an
[Okta auth backend within Vault](https://www.vaultproject.io/docs/auth/okta.html).

## Example Usage

```hcl
resource "vault_okta_auth_backend" "example" {
    description  = "Demonstration of the Terraform Okta auth backend"
    organization = "example"
    token        = "something that should be kept secret"
    
    group {
        group_name = "foo"
        policies   = ["one", "two"]
    }
    
    user {
        username = "bar"
        groups   = ["foo"]
    }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Optional) Path to mount the Okta auth backend. Default to path `okta`.

* `disable_remount` - (Optional) If set, opts out of mount migration on path updates.
  See here for more info on [Mount Migration](https://www.vaultproject.io/docs/concepts/mount-migration)

* `description` - (Optional) The description of the auth backend

* `org_name` - (Optional) The Okta organization. This will be the first part of the url `https://XXX.okta.com`.
  Exactly one of `org_name` or `organization` must be specified.

* `organization` - (Optional) **Deprecated: Use `org_name` instead.** The Okta organization. This will be the first part of the url `https://XXX.okta.com`.
  Exactly one of `org_name` or `organization` must be specified.

* `api_token` - (Optional) The Okta API token. This is required to query Okta for user group membership.
  If this is not supplied only locally configured groups will be enabled.
  Conflicts with `token` and `api_token_wo`.

* `token` - (Optional) **Deprecated: Use `api_token` instead.** The Okta API token. This is required to query Okta for user group membership.
  If this is not supplied only locally configured groups will be enabled.
  Conflicts with `api_token` and `api_token_wo`.

* `base_url` - (Optional) The Okta url. Examples: oktapreview.com, okta.com

* `bypass_okta_mfa` - (Optional) When true, requests by Okta for a MFA check will be bypassed. This also disallows certain status checks on the account, such as whether the password is expired.

* `api_token_wo_version` - (Optional) Version counter for the write-only `api_token_wo`.
  Increment this value to trigger an update of the write-only token. Required when using `api_token_wo`.

* `group` - (Optional) Associate Okta groups with policies within Vault.
[See below for more details](#okta-group).

* `user` - (Optional) Associate Okta users with groups or policies within Vault.
[See below for more details](#okta-user).

### Okta Group

* `group_name` - (Required) Name of the group within the Okta

* `policies` - (Optional) Vault policies to associate with this group

### Okta User

* `username` - (Required) Name of the user within Okta

* `groups` - (Optional) List of Okta groups to associate with this user

* `policies` - (Optional) List of Vault policies to associate with this user

* `tune` - (Optional) Extra configuration block. Structure is documented below.

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

* `token_num_uses` - (Optional) The [maximum number](https://www.vaultproject.io/api-docs/gcp#token_num_uses)
  of times a generated token may be used (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

* `alias_metadata` - (Optional) The metadata to be tied to generated entity alias.
  This should be a list or map containing the metadata in key value pairs.

## Ephemeral Attributes Reference

The following write-only attributes are supported:

* `api_token_wo` - (Optional) Write-only Okta API token. This is required to query Okta for user group membership.
  Use this for enhanced security when you don't want the token to appear in state files. Requires `api_token_wo_version`. Conflicts with `token` and `api_token`.
  **Note**: This property is write-only and will not be read from the API.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `accessor` - The mount accessor related to the auth mount. It is useful for integration with [Identity Secrets Engine](https://www.vaultproject.io/docs/secrets/identity/index.html).

## Import

Okta authentication backends can be imported using its `path`, e.g.

```
$ terraform import vault_okta_auth_backend.example okta
```
