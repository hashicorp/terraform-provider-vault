---
layout: "vault"
page_title: "Vault: vault_gcpkms_decrypt ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-gcpkms-decrypt"
description: |-
  Decrypts ciphertext using GCP KMS through Vault
---

# vault\_gcpkms\_decrypt

Decrypts ciphertext that was encrypted using a GCP KMS encryption key through Vault. This is an ephemeral
resource that performs decryption operations without storing the resulting plaintext in Terraform state.

## Example Usage

### Basic Decryption

```hcl
resource "vault_mount" "gcpkms" {
  path = "gcpkms"
  type = "gcpkms"
}

resource "vault_gcpkms_secret_backend" "gcpkms" {
  mount                  = vault_mount.gcpkms.path
  credentials_wo         = file("gcp-credentials.json")
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "encryption_key" {
  mount            = vault_mount.gcpkms.path
  name             = "my-key"
  key_ring         = "projects/my-project/locations/us-central1/keyRings/my-keyring"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
}

ephemeral "vault_gcpkms_decrypt" "data" {
  mount      = vault_mount.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = var.encrypted_data
}

output "decrypted_secret" {
  value     = ephemeral.vault_gcpkms_decrypt.data.plaintext
  sensitive = true
}
```

### Complete Encrypt-Decrypt Workflow

```hcl
ephemeral "vault_gcpkms_encrypt" "secret" {
  mount_id  = vault_mount.gcpkms.id
  mount     = vault_mount.gcpkms.path
  name      = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext = base64encode("my secret message")
}

ephemeral "vault_gcpkms_decrypt" "recovered" {
  mount      = vault_mount.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = ephemeral.vault_gcpkms_encrypt.secret.ciphertext
}

output "decrypted_value" {
  value     = ephemeral.vault_gcpkms_decrypt.recovered.plaintext
  sensitive = true
}
```

### Decryption with Additional Authenticated Data (AAD)

```hcl
ephemeral "vault_gcpkms_decrypt" "with_aad" {
  mount                         = vault_mount.gcpkms.path
  name                          = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext                    = var.encrypted_data
  additional_authenticated_data = base64encode("context-info")
}
```

### Decryption with Specific Key Version

```hcl
ephemeral "vault_gcpkms_decrypt" "versioned" {
  mount       = vault_mount.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext  = var.encrypted_data
  key_version = 1
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured
  [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount_id` - (Optional) Terraform ID of the `vault_mount` resource. Set this to
  `vault_mount.<name>.id` to guarantee the ephemeral resource is deferred until the
  GCP KMS secrets engine mount exists and is ready.

* `mount` - (Required) Path where the GCP KMS secrets engine is mounted.

* `name` - (Required) Name of the encryption key that was used to encrypt the data. The key must have
  purpose `encrypt_decrypt`.

* `ciphertext` - (Required, Sensitive) Base64-encoded ciphertext to decrypt. This should be the output
  from a previous [`vault_gcpkms_encrypt`](/docs/providers/vault/ephemeral-resources/gcpkms_secret_encrypt.html)
  operation.

* `additional_authenticated_data` - (Optional) Base64-encoded additional authenticated data (AAD) that
  was used during encryption. This must match exactly the AAD used during encryption, or decryption
  will fail.

* `key_version` - (Optional) Specific version of the key to use for decryption. If not specified, GCP
  KMS will automatically use the version that was used to encrypt the data.

## Attributes Reference

The following attributes are exported:

* `plaintext` - The base64-encoded decrypted plaintext. This value is marked as sensitive and will not
  appear in console output.
