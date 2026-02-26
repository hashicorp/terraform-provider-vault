---
layout: "vault"
page_title: "Vault: vault_kmip_secret_listener resource"
sidebar_current: "docs-vault-resource-kmip-secret-listener"
description: |-
  Manage KMIP Secret listeners in Vault.
---

# vault\_kmip\_secret\_listener

Manages KMIP Secret listeners in a Vault server. This feature requires
Vault Enterprise. See the [Vault documentation](https://www.vaultproject.io/docs/secrets/kmip)
for more information.

Listeners define the network configuration for KMIP servers, including the address to listen on,
TLS settings, and which CA to use for generating server certificates and verifying client certificates.

## Example Usage

### Basic Listener

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca" "example" {
  path     = vault_kmip_secret_backend.default.path
  name     = "example-ca"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_listener" "example" {
  path             = vault_kmip_secret_backend.default.path
  name             = "example-listener"
  ca               = vault_kmip_secret_ca.example.name
  address          = "0.0.0.0:5696"
  server_hostnames = ["kmip.example.com"]
}
```

### Listener with Advanced TLS Configuration

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca" "primary" {
  path     = vault_kmip_secret_backend.default.path
  name     = "primary-ca"
  key_type = "rsa"
  key_bits = 4096
}

resource "vault_kmip_secret_ca" "secondary" {
  path     = vault_kmip_secret_backend.default.path
  name     = "secondary-ca"
  key_type = "ec"
  key_bits = 256
}

resource "vault_kmip_secret_listener" "advanced" {
  path                = vault_kmip_secret_backend.default.path
  name                = "advanced-listener"
  ca                  = vault_kmip_secret_ca.primary.name
  address             = "0.0.0.0:5696"
  additional_client_cas = [vault_kmip_secret_ca.secondary.name]
  also_use_legacy_ca  = true
  server_ips          = ["192.168.1.100", "10.0.0.50"]
  server_hostnames    = ["kmip.example.com", "kmip-backup.example.com"]
  tls_min_version     = "tls13"
  tls_cipher_suites   = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) Path where KMIP backend is mounted. Must not begin or end with a `/`.

* `name` - (Required) Unique name for the listener.

* `ca` - (Required) Name of the CA to use to generate the server certificate and verify client certificates.

* `address` - (Required) Host:port address to listen on (e.g., `0.0.0.0:5696` or `127.0.0.1:8080`).

* `additional_client_cas` - (Optional) Names of additional TLS CAs to use to verify client certificates. This allows accepting client certificates from multiple CAs.

* `also_use_legacy_ca` - (Optional) Use the legacy unnamed CA for verifying client certificates as well. Defaults to `false`.

* `server_ips` - (Optional) IP SANs to include in the listener's server certificate. These IPs will be added as Subject Alternative Names in the certificate.

* `server_hostnames` - (Optional) DNS SANs to include in the listener's server certificate. These hostnames will be added as Subject Alternative Names in the certificate.

* `tls_min_version` - (Optional) Minimum TLS version to accept. Valid values are `tls12` or `tls13`.

* `tls_max_version` - (Optional) Maximum TLS version to accept. Valid values are `tls12` or `tls13`.

* `tls_cipher_suites` - (Optional) Comma-separated list of TLS cipher suites to allow. This setting does not apply to TLS 1.3 and later. Example: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The ID of the listener in the format `<path>/listener/<name>`.

## Import

KMIP Secret listener can be imported using the format `<path>/listener/<name>`, e.g.

```
$ terraform import vault_kmip_secret_listener.example kmip/listener/example-listener
```

## Notes

* The listener requires a CA to be configured first using `vault_kmip_secret_ca`.
* The `address` must be a valid host:port combination.
* When `server_ips` or `server_hostnames` are specified, they will be included in the server certificate as Subject Alternative Names (SANs).
* The `additional_client_cas` parameter allows you to accept client certificates from multiple CAs, useful for certificate rotation scenarios.
* TLS cipher suites configuration only applies to TLS 1.2 and earlier versions.