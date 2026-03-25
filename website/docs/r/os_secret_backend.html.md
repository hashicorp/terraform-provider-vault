---
layout: "vault"
page_title: "Vault: vault_os_secret_backend resource"
sidebar_current: "docs-vault-resource-os-secret-backend"
description: |-
  Manages OS Secrets Engine backends in Vault.
---

# vault\_os\_secret\_backend

Manages OS Secrets Engine backends in a Vault server. The OS Secrets Engine manages credentials
for operating system accounts on remote hosts via SSH. This resource requires Vault 2.0.0 or later.

See the [Vault documentation](https://www.vaultproject.io/docs/secrets/os) for more information.

## Example Usage

### Basic Configuration

```hcl
resource "vault_os_secret_backend" "os" {
  path        = "os"
  description = "OS secrets engine for managing SSH credentials"
}
```

### Advanced Configuration

```hcl
resource "vault_os_secret_backend" "os" {
  path                             = "os-prod"
  description                      = "Production OS secrets engine"
  max_versions                     = 10
  ssh_host_key_trust_on_first_use  = true
  password_policy                  = "complex-password-policy"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) The path where the OS secrets engine will be mounted. Must not begin or end with a `/`.

* `description` - (Optional) A human-friendly description of the mount.

* `max_versions` - (Optional) The maximum number of versions to keep for SSH host keys. Set to `0` for unlimited versions. Defaults to `0`.

* `ssh_host_key_trust_on_first_use` - (Optional) If `true`, SSH host keys will be trusted on first use (TOFU). If `false`, host keys must be explicitly configured. Defaults to `false`.

* `password_policy` - (Optional) The name of the password policy to use when generating passwords for managed accounts. If not specified, Vault will use its default password generation.

* `disable_remount` - (Optional) If set, opts out of mount migration on path updates.
  See here for more info on [Mount Migration](https://www.vaultproject.io/docs/concepts/mount-migration)

### Common Mount Arguments

These arguments are common across all resources that mount a secret engine.

* `default_lease_ttl_seconds` - (Optional) Default lease duration for tokens and secrets in seconds

* `max_lease_ttl_seconds` - (Optional) Maximum possible lease duration for tokens and secrets in seconds

* `audit_non_hmac_response_keys` - (Optional) Specifies the list of keys that will not be HMAC'd by audit devices in the response data object.

* `audit_non_hmac_request_keys` - (Optional) Specifies the list of keys that will not be HMAC'd by audit devices in the request data object.

* `local` - (Optional) Boolean flag that can be explicitly set to true to enforce local mount in HA environment

* `options` - (Optional) Specifies mount type specific options that are passed to the backend

* `seal_wrap` - (Optional) Boolean flag that can be explicitly set to true to enable seal wrapping for the mount, causing values stored by the mount to be wrapped by the seal's encryption capability

* `external_entropy_access` - (Optional) Boolean flag that can be explicitly set to true to enable the secrets engine to access Vault's external entropy source

* `allowed_managed_keys` - (Optional) Set of managed key registry entry names that the mount in question is allowed to access

* `listing_visibility` - (Optional) Specifies whether to show this mount in the UI-specific
  listing endpoint. Valid values are `unauth` or `hidden`. If not set, behaves like `hidden`.

* `passthrough_request_headers` - (Optional) List of headers to allow and pass from the request to
  the plugin.

* `allowed_response_headers` - (Optional) List of headers to allow, allowing a plugin to include
  them in the response.

* `delegated_auth_accessors` - (Optional)  List of allowed authentication mount accessors the
  backend can request delegated authentication for.

* `plugin_version` - (Optional) Specifies the semantic version of the plugin to use, e.g. "v1.0.0".
  If unspecified, the server will select any matching unversioned plugin that may have been
  registered, the latest versioned plugin registered, or a built-in plugin in that order of precedence.

* `identity_token_key` - (Optional)  The key to use for signing plugin workload identity tokens. If
  not provided, this will default to Vault's OIDC default key. Requires Vault Enterprise 1.16+.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

OS Secret backend can be imported using the `path`, e.g.

```
$ terraform import vault_os_secret_backend.os os
```

## Notes

* This resource requires Vault 2.0.0 or later.
* The OS Secrets Engine must be enabled before hosts and accounts can be configured.
* When `ssh_host_key_trust_on_first_use` is enabled, the first connection to a host will automatically trust and store its SSH host key.
* The `password_policy` must reference an existing password policy in Vault. See `vault_password_policy` resource for creating password policies.
* Changing the `path` will cause the backend to be remounted at the new path.