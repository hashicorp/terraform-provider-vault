---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_export_key resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-export-key"
description: |-
  Manages a wrapping keypair on a PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_export\_key

Manages a wrapping keypair on a PKI secrets engine mount. Vault stores the private half internally and returns the public key and its HMAC fingerprint.

For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/pki#export-key-management) for PKI export key management.

*Available only for Vault Enterprise*.

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path = "pki"
  type = "pki"
}

resource "vault_pki_secret_backend_export_key" "example" {
  mount    = vault_mount.pki.path
  key_type = "ec-p256"
  name     = "example-wrapping-key"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path of the PKI secrets engine mount. Changing this field forces a new resource.

* `key_type` - (Required) Algorithm for the wrapping keypair. Supported values: `rsa-2048`, `rsa-3072`, `rsa-4096`, `rsa-8192`, `ec-p256`, `ec-p384`, `ec-p521`, `ml-kem-768`, `ml-kem-1024`. Changing this field forces a new resource.

* `name` - (Optional) Human-readable name for this export key. Changing this field forces a new resource.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `export_key_uuid` - UUID assigned by Vault to this export key.

* `public_key` - PKIX PEM-encoded public key returned by Vault.

* `export_key_hmac` - Deterministic HMAC fingerprint of the public key (format `sha256:<hex>`).

* `created_at` - RFC3339 timestamp of when this export key was created.

## Import

PKI export keys can be imported using the `<mount>/export/<uuid>` format, e.g.

```
$ terraform import vault_pki_secret_backend_export_key.example pki/export/bf9b0d48-d0dd-652c-30be-77d04fc7e94d
```
