---
layout: "vault"
page_title: "Vault: vault_auth_tune resource"
sidebar_current: "docs-vault-resource-auth-tune"
description: |-
  Tunes an existing Vault auth mount.
---

# vault\_auth\_tune

Manages tune settings on an auth mount created by `vault_auth_backend` or another auth method resource.

Terraform manages only the arguments you set; other settings keep their current value. Removing an argument resets it to Vault's default, and destroying the resource resets everything it managed.

~> **Important** Do not combine this resource with a `tune` block on the auth
resource for the same mount. They overwrite each other's settings.

To migrate, delete the `tune` block and add `vault_auth_tune` with the same values. Deleting the block doesn't recreate the mount or change its settings.

## Example Usage

Set lease TTLs, token type, and user lockout on a userpass mount:

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

Show Okta on the UI login page:

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
  `unauth` shows the method on the UI login page; `hidden` hides it.

* `passthrough_request_headers` - (Optional) Headers to pass from the request to the auth method.

* `allowed_response_headers` - (Optional) Headers an auth method may include in the response.

* `token_type` - (Optional) Type of tokens the mount returns.
  Valid values are `default-service`, `default-batch`, `service`, and `batch`.

* `plugin_version` - (Optional) Semantic version of the plugin to use, for example `v1.0.0`.
  A change does not take effect until the plugin is reloaded.

* `user_lockout_config` - (Optional) A block that configures user lockout.
  Supported for `approle`, `ldap`, and `userpass`. Requires Vault 1.13.0 or later.

### User lockout options

* `lockout_threshold` - (Optional) Failed login attempts before lockout, for example `15`.

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

Import reads the mount's current non-default settings. Add each one to your configuration before the next apply, or it will be reset to Vault's default.
