---
layout: "vault"
page_title: "Vault: vault_auth_tune resource"
sidebar_current: "docs-vault-resource-auth-tune"
description: |-
  Tunes an existing Vault auth mount.
---

# vault\_auth\_tune

Tunes an auth mount that already exists. The auth method itself stays on
`vault_auth_backend` or a dedicated auth resource. Add `vault_auth_tune` when
a mount needs tuning, and leave it out until then. The auth mount is not
recreated.

Unset arguments are not written to Vault and are not stored from Vault's tune
response. A plan does not fill in server defaults such as `token_type` for
arguments you left out. Removing an argument clears that setting. Destroying
the resource clears every setting it managed.

~> **Important** Do not combine this resource with a `tune` block on the auth
resource for the same mount. Both write to the mount tune API.

The `tune` block on an auth method resource is optional and computed. Removing
it does not recreate the mount, and the mount keeps its current tune. Add
`vault_auth_tune` for the settings Terraform should manage. The same pattern
works for Okta and SAML mounts that need `listing_visibility = "unauth"`.

Changing `path` replaces this resource only. It does not move the auth mount.

## Example Usage

```hcl
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

resource "vault_auth_tune" "userpass" {
  path              = vault_auth_backend.userpass.path
  default_lease_ttl = "12h"
  max_lease_ttl     = "72h"
  token_type        = "batch"

  user_lockout_config {
    lockout_threshold     = "5"
    lockout_duration      = "15m"
    lockout_counter_reset = "15m"
    lockout_disable       = true
  }
}
```

```hcl
resource "vault_okta_auth_backend" "example" {
  org_name = "example"
}

resource "vault_auth_tune" "okta" {
  path               = vault_okta_auth_backend.example.path
  listing_visibility = "unauth"
}
```

## Argument Reference

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Required) Path of the auth mount to tune, without a leading `auth/`.
  Changing this value replaces the tune resource and does not remount the auth method.

* `default_lease_ttl` - (Optional) Default time-to-live for the mount.
  Must be a valid [duration string](https://pkg.go.dev/time#ParseDuration).
  Remove this argument to reset the mount to the system default.

* `max_lease_ttl` - (Optional) Maximum time-to-live for the mount.
  Must be a valid [duration string](https://pkg.go.dev/time#ParseDuration).
  Remove this argument to reset the mount to the system default.

* `audit_non_hmac_request_keys` - (Optional) Keys that will not be HMAC'd by audit devices in the request data.

* `audit_non_hmac_response_keys` - (Optional) Keys that will not be HMAC'd by audit devices in the response data.

* `listing_visibility` - (Optional) Whether to show this mount in the UI listing endpoint.
  Valid values are `unauth` and `hidden`.

* `passthrough_request_headers` - (Optional) Headers to pass from the request to the auth method.

* `allowed_response_headers` - (Optional) Headers an auth method may include in the response.

* `token_type` - (Optional) Type of tokens the mount returns.
  Valid values are `default-service`, `default-batch`, `service`, and `batch`.

* `plugin_version` - (Optional) Semantic version of the plugin to use, for example `v1.0.0`.
  A change does not take effect until the plugin is reloaded.

* `user_lockout_config` - (Optional) A block that configures user lockout.
  Supported for `approle`, `ldap`, and `userpass`. Requires Vault 1.13.0 or later.

### User lockout options

* `lockout_threshold` - (Optional) Failed login attempts before lockout, as a string such as `15`.

* `lockout_duration` - (Optional) How long a user stays locked out, as a duration such as `15m`.

* `lockout_counter_reset` - (Optional) How long with no failures before the counter resets, as a duration such as `15m`.

* `lockout_disable` - (Optional) Disables user lockout for this mount when true.

## Attributes Reference

No additional attributes are exported.

## Import

Import using the auth mount path.

```
$ terraform import vault_auth_tune.userpass userpass
```

Import reads the mount tune. Non-empty values are stored, including lease TTLs,
`listing_visibility`, and `token_type`. Lockout fields are stored when they
differ from Vault's defaults. Copy the imported values into configuration
before the next apply. Arguments left out of configuration are cleared.
