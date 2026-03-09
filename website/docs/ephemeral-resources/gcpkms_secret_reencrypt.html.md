---
layout: "vault"
page_title: "Vault: vault_gcpkms_reencrypt ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-gcpkms-reencrypt"
description: |-
  Re-encrypts ciphertext using GCP KMS through Vault
---

# vault\_gcpkms\_reencrypt

Re-encrypts ciphertext using a GCP KMS encryption key through Vault. This is useful for key rotation
scenarios where you want to update ciphertext to use a newer key version without decrypting and
re-encrypting locally.

This is an ephemeral resource that performs re-encryption operations without storing sensitive data in
Terraform state.

## Example Usage

### Basic Re-encryption

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
  rotation_period  = "2592000s"
}

ephemeral "vault_gcpkms_reencrypt" "rotated" {
  mount      = vault_mount.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = var.old_encrypted_data
}

resource "aws_ssm_parameter" "rotated_secret" {
  name  = "/myapp/rotated-data"
  type  = "String"
  value = ephemeral.vault_gcpkms_reencrypt.rotated.new_ciphertext
}
```

### Key Rotation Workflow

```hcl
ephemeral "vault_gcpkms_encrypt" "original" {
  mount_id    = vault_mount.gcpkms.id
  mount       = vault_mount.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext   = base64encode("sensitive data")
  key_version = 1
}

# After key rotation, re-encrypt to use latest version
ephemeral "vault_gcpkms_reencrypt" "updated" {
  mount      = vault_mount.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = ephemeral.vault_gcpkms_encrypt.original.ciphertext
}
```

### Re-encryption with Additional Authenticated Data (AAD)

```hcl
ephemeral "vault_gcpkms_reencrypt" "with_aad" {
  mount                         = vault_mount.gcpkms.path
  name                          = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext                    = var.old_encrypted_data
  additional_authenticated_data = base64encode("context-info")
}
```

### Re-encryption to Specific Key Version

```hcl
ephemeral "vault_gcpkms_reencrypt" "versioned" {
  mount       = vault_mount.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext  = var.old_encrypted_data
  key_version = 3
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

* `name` - (Required) Name of the encryption key to use for re-encryption. The key must have purpose
  `encrypt_decrypt`.

* `ciphertext` - (Required, Sensitive) Base64-encoded ciphertext to re-encrypt. This should be data
  that was previously encrypted using the same key.

* `additional_authenticated_data` - (Optional) Base64-encoded additional authenticated data (AAD)
  associated with the ciphertext. The same AAD must be provided as was used during the original
  encryption.

* `key_version` - (Optional) Specific target key version to re-encrypt to. If not specified, the
  ciphertext will be re-encrypted using the latest key version.

## Attributes Reference

The following attributes are exported:

* `new_ciphertext` - The base64-encoded re-encrypted ciphertext. This value is marked as sensitive
  and will not appear in console output.

