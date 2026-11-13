---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_wrapped_key_import resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-wrapped-key-import"
description: |-
  Imports a wrapped CA private key into a PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_wrapped\_key\_import

Imports a wrapped CA private key into a PKI secrets engine mount.

For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/pki#import-key) for importing a key.

*Available only for Vault Enterprise*.


## Example Usage

```hcl
resource "vault_mount" "pki" {
  path = "pki"
  type = "pki"
}

resource "vault_pki_secret_backend_wrapped_key_import" "example" {
  mount           = vault_mount.pki.path
  key_name        = "example-key"
  wrapped_key     = "..."
  export_key_hmac = "sha256:..."
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path of the destination PKI secrets engine mount. Changing this field forces a new resource.

* `key_name` - (Optional) Human-readable name for the imported key in Vault. Changing this field forces a new resource.

* `wrapped_key` - (Required) Base64-encoded wrapped CA private key blob. Write-only — sent to Vault on create and never stored in Terraform state. Accepts ephemeral values.

* `export_key_hmac` - (Required) Deterministic HMAC fingerprint of the wrapping key used to encrypt the blob. Write-only — not stored in state after create. Accepts ephemeral values.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `key_id` - UUID assigned by Vault to the imported key.

* `key_type` - Key algorithm type as reported by Vault after import (e.g. `rsa`, `ec`, `ed25519`).
