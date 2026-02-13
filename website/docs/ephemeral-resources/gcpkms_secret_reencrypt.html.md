---
layout: "vault"
page_title: "Vault: vault_gcpkms_secret_reencrypt ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-gcpkms-secret-reencrypt"
description: |-
  Re-encrypts ciphertext using GCP KMS through Vault
---

# vault\_gcpkms\_reencrypt

Re-encrypts ciphertext using the latest version of a GCP KMS encryption key through Vault. This is useful for 
key rotation scenarios where you want to update ciphertext to use a newer key version without decrypting 
and re-encrypting locally.

This is an ephemeral resource that performs re-encryption operations without storing sensitive data in state.

## Example Usage

### Basic Re-encryption

```hcl
resource "vault_gcpkms_secret_backend" "gcpkms" {
  path        = "gcpkms"
  credentials = file("gcp-credentials.json")
}

resource "vault_gcpkms_secret_backend_key" "encryption_key" {
  backend          = vault_gcpkms_secret_backend.gcpkms.path
  name             = "my-key"
  key_ring         = "projects/my-project/locations/us-central1/keyRings/my-keyring"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
  rotation_period  = "2592000s"  # 30 days
}

ephemeral "vault_gcpkms_reencrypt" "rotated" {
  backend    = vault_gcpkms_secret_backend.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = var.old_encrypted_data
  mount_id   = vault_gcpkms_secret_backend.gcpkms.id
}

# Store the re-encrypted data
resource "aws_ssm_parameter" "rotated_secret" {
  name  = "/myapp/rotated-data"
  type  = "String"
  value = ephemeral.vault_gcpkms_reencrypt.rotated.new_ciphertext
}
```

### Key Rotation Workflow

```hcl
# Original encryption with version 1
ephemeral "vault_gcpkms_encrypt" "original" {
  backend     = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext   = base64encode("sensitive data")
  key_version = 1
  mount_id    = vault_gcpkms_secret_backend.gcpkms.id
}

# After key rotation, re-encrypt to use latest version
ephemeral "vault_gcpkms_reencrypt" "updated" {
  backend    = vault_gcpkms_secret_backend.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = ephemeral.vault_gcpkms_encrypt.original.ciphertext
  mount_id   = vault_gcpkms_secret_backend.gcpkms.id
}

# Verify with latest version
ephemeral "vault_gcpkms_decrypt" "verify" {
  backend    = vault_gcpkms_secret_backend.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = ephemeral.vault_gcpkms_reencrypt.updated.new_ciphertext
  mount_id   = vault_gcpkms_secret_backend.gcpkms.id
}
```

### Batch Re-encryption for Multiple Items

```hcl
locals {
  encrypted_items = {
    "item1" = "encrypted_value_1"
    "item2" = "encrypted_value_2"
    "item3" = "encrypted_value_3"
  }
}

ephemeral "vault_gcpkms_reencrypt" "items" {
  for_each = local.encrypted_items
  
  backend    = vault_gcpkms_secret_backend.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = each.value
  mount_id   = vault_gcpkms_secret_backend.gcpkms.id
}

output "reencrypted_items" {
  value = {
    for key, resource in ephemeral.vault_gcpkms_reencrypt.items :
    key => resource.new_ciphertext
  }
  sensitive = true
  ephemeral = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) Path where the GCP KMS secrets engine is mounted.

* `name` - (Required) Name of the encryption key to use for re-encryption. This must reference a key with 
  purpose `encrypt_decrypt`.

* `ciphertext` - (Required) The base64-encoded ciphertext to re-encrypt. This should be data that was previously 
  encrypted using the same key.

* `additional_authenticated_data` - (Optional) Additional authenticated data (AAD) that was used during the 
  original encryption, base64-encoded. If AAD was used, it must be provided here.

* `key_version` - (Optional) Specific version of the key to use for re-encryption. If not specified, the key's 
  primary (latest) version will be used.

* `mount_id` - (Required) The unique identifier for the Vault mount. This forces Terraform to wait until the mount
  is fully configured before performing re-encryption operations.

## Attributes Reference

The following attributes are exported:

* `new_ciphertext` - The base64-encoded re-encrypted ciphertext using the latest key version. This ciphertext can be 
  decrypted using any version of the key that is within the configured version range.

