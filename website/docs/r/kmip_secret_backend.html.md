---
layout: "vault"
page_title: "Vault: vault_kmip_secret_backend resource"
sidebar_current: "docs-vault-resource-kmip-secret-backend"
description: |-
  Provision KMIP Secret backends in Vault.
---

# vault\_kmip\_secret\_backend

Manages KMIP Secret backends in a Vault server. This feature requires
Vault Enterprise. See the [Vault documentation](https://www.vaultproject.io/docs/secrets/kmip)
for more information.

## Example Usage

```hcl
resource "vault_kmip_secret_backend" "default" {
  path                        = "kmip"
  description                 = "Vault KMIP backend"
  listen_addrs                = ["127.0.0.1:5696", "127.0.0.1:8080"]
  tls_ca_key_type             = "rsa"
  tls_ca_key_bits             = 4096
  default_tls_client_key_type = "rsa"
  default_tls_client_key_bits = 4096
  default_tls_client_ttl      = 86400
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) The unique path this backend should be mounted at. Must
  not begin or end with a `/`. Defaults to `kmip`.

* `disable_remount` - (Optional) If set, opts out of mount migration on path updates.
  See here for more info on [Mount Migration](https://www.vaultproject.io/docs/concepts/mount-migration)

* `listen_addrs` - (Optional) Addresses the KMIP server should listen on (`host:port`).

* `server_hostnames` - (Optional) Hostnames to include in the server's TLS certificate as SAN DNS names. The first will be used as the common name (CN).

* `server_ips` - (Optional) IPs to include in the server's TLS certificate as SAN IP addresses.

* `tls_ca_key_type` - (Optional) CA key type, rsa or ec.

* `tls_ca_key_bits` - (Optional) CA key bits, valid values depend on key type.

* `tls_min_version` - (Optional) Minimum TLS version to accept.

* `default_tls_client_key_type` - (Optional) Client certificate key type, `rsa` or `ec`.

* `default_tls_client_key_bits` - (Optional) Client certificate key bits, valid values depend on key type.

* `default_tls_client_key_type` - (Optional) Client certificate key type, `rsa` or `ec`.

### Common Mount Arguments
These arguments are common across all resources that mount a secret engine.

* `description` - (Optional) Human-friendly description of the mount

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

KMIP Secret backend can be imported using the `path`, e.g.

```
$ terraform import vault_kmip_secret_backend.default kmip
```
