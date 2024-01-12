---
layout: "vault"
page_title: "Vault: vault_auth_tune resource"
sidebar_current: "docs-vault-resource-auth-tune"
description: |-
  Writes auth method tuning for Vault
---

# vault\_auth\_tune

~> **Important** Some resources support tuning of an auth method directly, and
  therefore may present a conflict or configuration loop if used in conjunction
  with `vault_auth_tune`. This resource is intended to be used in situations
  where an auth method or mount is not tuned via alternative methods.`

## Example Usage

```hcl
resource "vault_auth_tune" "example" {
  path = vault_auth_backend.approle.path

  default_lease_ttl  = "12h"
  max_lease_ttl      = "72h"
  listing_visibility = "hidden"
  token_type         = "service"

  user_lockout_config {
    lockout_disable       = false
    lockout_threshold     = "10"
    lockout_duration      = "60s"
    lockout_counter_reset = "1h"
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) The path to mount the auth method to tune.

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

* `plugin_version` - (Optional) Specifies the semantic version of the plugin to
  use, e.g. \"v1.0.0\". Changes will not take effect until the mount is reloaded.

* `user_lockout_config` - (Optional) A nested block containing configuration
  options for user lockout. User lockout feature was added in Vault 1.13.

### User Lockout Options

* `lockout_threshold` - (Optional) Specifies the number of failed login attempts
  after which the user is locked out, specified as a string like \"15\".

* `lockout_duration` - (Optional) Specifies the duration for which an user will
  be locked out, specified as a string duration like \"5s\" or \"30m\"..

* `lockout_counter_reset` - (Optional) Specifies the duration after which the
  lockout counter is reset with no failed login attempts, specified as a string
  duration like \"5s\" or \"30m\".

* `lockout_disable` - (Optional) Disables the user lockout feature for this
  mount if set to true. Defaults to false.

## Import

Auth method tuning can be imported using the `path`, e.g.

```
$ terraform import vault_auth_tune.example approle
```
