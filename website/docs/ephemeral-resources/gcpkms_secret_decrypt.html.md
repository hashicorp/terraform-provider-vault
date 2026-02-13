---
layout: "vault"
page_title: "Vault: vault_gcpkms_secret_decrypt ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-gcpkms-secret-decrypt"
description: |-
  Decrypts ciphertext using GCP KMS through Vault
---

# vault\_gcpkms\_decrypt

Decrypts ciphertext that was encrypted using a GCP KMS encryption key through Vault. This is an ephemeral 
resource that performs decryption operations without storing the resulting plaintext in state.

Ephemeral resources are ideal for cryptographic operations as they don't persist sensitive data in 
Terraform state files.

## Example Usage

### Basic Decryption

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
}

ephemeral "vault_gcpkms_decrypt" "data" {
  backend    = vault_gcpkms_secret_backend.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = var.encrypted_data
  mount_id   = vault_gcpkms_secret_backend.gcpkms.id
}

# Use the decrypted plaintext
output "decrypted_secret" {
  value     = base64decode(ephemeral.vault_gcpkms_decrypt.data.plaintext)
  sensitive = true
  ephemeral = true
}
```

### Decryption with Specific Key Version

~> **Note:** The `key_version` parameter is optional and rarely needed for decryption. GCP KMS automatically 
determines the correct key version from the ciphertext metadata. Only specify this if you need to enforce 
decryption with a specific version.

```hcl
ephemeral "vault_gcpkms_decrypt" "versioned" {
  backend     = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext  = var.encrypted_data
  key_version = 1
  mount_id    = vault_gcpkms_secret_backend.gcpkms.id
}
```

### Decryption with Additional Authenticated Data (AAD)

```hcl
ephemeral "vault_gcpkms_decrypt" "with_aad" {
  backend                       = vault_gcpkms_secret_backend.gcpkms.path
  name                          = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext                    = var.encrypted_data
  additional_authenticated_data = base64encode("context-info")
  mount_id                      = vault_gcpkms_secret_backend.gcpkms.id
}
```

### Complete Encrypt-Decrypt Example

```hcl
ephemeral "vault_gcpkms_encrypt" "secret" {
  backend   = vault_gcpkms_secret_backend.gcpkms.path
  name      = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext = base64encode("my secret message")
  mount_id  = vault_gcpkms_secret_backend.gcpkms.id
}

ephemeral "vault_gcpkms_decrypt" "recovered" {
  backend    = vault_gcpkms_secret_backend.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = ephemeral.vault_gcpkms_encrypt.secret.ciphertext
  mount_id   = vault_gcpkms_secret_backend.gcpkms.id
}

# Will output: "my secret message"
output "decrypted_value" {
  value     = base64decode(ephemeral.vault_gcpkms_decrypt.recovered.plaintext)
  sensitive = true
  ephemeral = true
}
```

### Decrypting Data from SSM Parameter

```hcl
data "aws_ssm_parameter" "encrypted_secret" {
  name = "/myapp/encrypted-data"
}

ephemeral "vault_gcpkms_decrypt" "from_ssm" {
  backend    = vault_gcpkms_secret_backend.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = data.aws_ssm_parameter.encrypted_secret.value
  mount_id   = vault_gcpkms_secret_backend.gcpkms.id
}

output "secret_value" {
  value     = base64decode(ephemeral.vault_gcpkms_decrypt.from_ssm.plaintext)
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

* `name` - (Required) Name of the encryption key that was used to encrypt the data. This must reference a key 
  with purpose `encrypt_decrypt`.

* `ciphertext` - (Required) The base64-encoded ciphertext to decrypt. This should be the output from a previous 
  `vault_gcpkms_encrypt` operation.

* `key_version` - (Optional) Specific version of the key to use for decryption. **Note:** This is rarely needed 
  as GCP KMS automatically determines the correct version from the ciphertext metadata. Only specify this if you 
  need to enforce decryption with a specific version.

* `additional_authenticated_data` - (Optional) Additional authenticated data (AAD) that was used during encryption,
  base64-encoded. This must match exactly the AAD used during encryption, or decryption will fail.

* `mount_id` - (Required) The unique identifier for the Vault mount. This forces Terraform to wait until the mount
  is fully configured before performing decryption operations.

## Attributes Reference

The following attributes are exported:

* `plaintext` - The decrypted plaintext data, base64-encoded. This value is marked as sensitive and will not 
  appear in console output. Use `base64decode()` to get the original plaintext.
