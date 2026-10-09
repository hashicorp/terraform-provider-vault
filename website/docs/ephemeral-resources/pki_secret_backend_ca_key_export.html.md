---
layout: "vault"
page_title: "Vault: ephemeral vault_pki_secret_backend_ca_key_export resource"
sidebar_current: "docs-vault-ephemeral-pki-secret-backend-ca-key-export"
description: |-
  Wraps a CA private key for migration. The wrapped key is never written to Terraform state.
---

# vault\_pki\_secret\_backend\_ca\_key\_export

Wraps a CA private key with a public key and returns the encrypted blob.

For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/pki#export-ca-key) for exporting a CA key.

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path = "pki"
  type = "pki"
}

resource "vault_pki_secret_backend_root_cert" "root_ca" {
  backend     = vault_mount.pki.path
  type        = "internal"
  common_name = "Example Root CA"
  key_type    = "rsa"
  key_bits    = 2048
}

ephemeral "vault_pki_secret_backend_ca_key_export" "wrapped" {
  mount       = vault_mount.pki.path
  mount_id    = vault_mount.pki.id
  ca_key_uuid = vault_pki_secret_backend_root_cert.root_ca.key_id
  public_key  = "-----BEGIN PUBLIC KEY-----\n..."
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path of the PKI secrets engine mount.

* `ca_key_uuid` - (Required) UUID of the CA key to export from the mount.

* `public_key` - (Required) PEM-encoded public key of the wrapping keypair.

* `mount_id` - (Optional) The `id` of the PKI mount resource. When set, Terraform defers
  the `Open` call until the mount is created.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `wrapped_key` - Base64-encoded encrypted blob containing the wrapped CA private key.

* `export_key_hmac` - HMAC fingerprint of the wrapping public key.

* `exported_at` - RFC3339 timestamp of when the export occurred.
