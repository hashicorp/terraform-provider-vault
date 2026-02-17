---
layout: "vault"
page_title: "Vault: vault_kmip_secret_ca_generated resource"
sidebar_current: "docs-vault-resource-kmip-secret-ca-generated"
description: |-
  Manage generated KMIP Secret CAs in Vault.
---

# vault\_kmip\_secret\_ca\_generated

Manages generated KMIP Secret CAs in a Vault server. This resource generates a new CA certificate and private key. This feature requires Vault Enterprise. See the [Vault documentation](https://www.vaultproject.io/docs/secrets/kmip) for more information.

## Example Usage

### Generate an EC CA

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca_generated" "ec" {
  path     = vault_kmip_secret_backend.default.path
  name     = "my-ec-ca"
  key_type = "ec"
  key_bits = 256
  ttl      = 31536000 # 1 year in seconds
}
```

### Generate an RSA CA

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca_generated" "rsa" {
  path     = vault_kmip_secret_backend.default.path
  name     = "my-rsa-ca"
  key_type = "rsa"
  key_bits = 2048
}
```

### Generate a CA with Custom TTL

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_ca_generated" "custom_ttl" {
  path     = vault_kmip_secret_backend.default.path
  name     = "long-lived-ca"
  key_type = "ec"
  key_bits = 384
  ttl      = 63072000 # 2 years in seconds
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) Path where KMIP backend is mounted. Must not begin or end with a `/`.

* `name` - (Required) Name to identify the CA. This will be used in the CA's path.

* `key_type` - (Required) CA key type. Valid values are `rsa` or `ec`.

* `key_bits` - (Required) CA key bits. Valid values depend on `key_type`:
  - For `rsa`: 2048, 3072, 4096
  - For `ec`: 224, 256, 384, 521

* `ttl` - (Optional) CA TTL in seconds. Defaults to 365 days (31536000 seconds).

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The ID of the CA in the format `<path>/ca/<name>`.

* `ca_pem` - The generated CA certificate in PEM format.

## Import

KMIP Secret CA Generated can be imported using the format `<path>/ca/<name>`, e.g.

```
$ terraform import vault_kmip_secret_ca_generated.example kmip/ca/my-ca
```

**Note:** When importing, the `key_type`, `key_bits`, and `ttl` values cannot be retrieved from Vault and will need to be set in your configuration. These values will be ignored during import verification.