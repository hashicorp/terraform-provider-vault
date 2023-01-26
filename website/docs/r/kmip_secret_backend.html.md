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
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) The unique path this backend should be mounted at. Must
  not begin or end with a `/`. Defaults to `kmip`.

* `disable_remount` - (Optional) If set, opts out of mount migration on path updates.
  See here for more info on [Mount Migration](https://www.vaultproject.io/docs/concepts/mount-migration)

* `description` - (Optional) A human-friendly description for this backend.

* `listen_addrs` - (Optional) Addresses the KMIP server should listen on (`host:port`).

* `server_hostnames` - (Optional) Hostnames to include in the server's TLS certificate as SAN DNS names. The first will be used as the common name (CN).

* `server_ips` - (Optional) IPs to include in the server's TLS certificate as SAN IP addresses.

* `tls_ca_key_type` - (Optional) CA key type, rsa or ec.

* `tls_ca_key_bits` - (Optional) CA key bits, valid values depend on key type.

* `tls_min_version` - (Optional) Minimum TLS version to accept.

* `default_tls_client_key_type` - (Optional) Client certificate key type, `rsa` or `ec`.

* `default_tls_client_key_bits` - (Optional) Client certificate key bits, valid values depend on key type.

* `default_tls_client_key_type` - (Optional) Client certificate key type, `rsa` or `ec`.



## Attributes Reference

No additional attributes are exported by this resource.

## Import

KMIP Secret backend can be imported using the `path`, e.g.

```
$ terraform import vault_kmip_secret_backend.default kmip
```
