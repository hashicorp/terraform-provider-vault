---
layout: "vault"
page_title: "Vault: vault_gcpkms_encrypt ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-gcpkms-encrypt"
description: |-
  Encrypts plaintext using GCP KMS through Vault
---

# vault\_gcpkms\_encrypt

Encrypts plaintext data using a GCP KMS encryption key through Vault. This is an ephemeral resource that 
performs encryption operations without storing the resulting ciphertext in state.

Ephemeral resources are ideal for cryptographic operations as they don't persist sensitive data in 
Terraform state files.

## Example Usage

### Basic Encryption

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

ephemeral "vault_gcpkms_encrypt" "data" {
  backend   = vault_gcpkms_secret_backend.gcpkms.path
  name      = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext = base64encode("sensitive data to encrypt")
  mount_id  = vault_gcpkms_secret_backend.gcpkms.id
}

# Use the ciphertext in another resource
resource "aws_ssm_parameter" "encrypted_secret" {
  name  = "/myapp/encrypted-data"
  type  = "String"
  value = ephemeral.vault_gcpkms_encrypt.data.ciphertext
}
```

### Encryption with Specific Key Version

```hcl
ephemeral "vault_gcpkms_encrypt" "versioned" {
  backend     = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext   = base64encode("sensitive data")
  key_version = 1
  mount_id    = vault_gcpkms_secret_backend.gcpkms.id
}
```

### Encryption with Additional Authenticated Data (AAD)

```hcl
ephemeral "vault_gcpkms_encrypt" "with_aad" {
  backend                       = vault_gcpkms_secret_backend.gcpkms.path
  name                          = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext                     = base64encode("sensitive data")
  additional_authenticated_data = base64encode("context-info")
  mount_id                      = vault_gcpkms_secret_backend.gcpkms.id
}
```

### Encrypt-Decrypt Workflow

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

# Will output: "my secret message" (base64-decoded)
output "decrypted_value" {
  value     = base64decode(ephemeral.vault_gcpkms_decrypt.recovered.plaintext)
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

* `name` - (Required) Name of the encryption key to use. This must reference a key with purpose `encrypt_decrypt`.

* `plaintext` - (Required, Sensitive) The plaintext data to encrypt, base64-encoded.

* `key_version` - (Optional) Specific version of the key to use for encryption. If not specified, the key's 
  primary version will be used.

* `additional_authenticated_data` - (Optional) Additional authenticated data (AAD) to include in the encryption, 
  base64-encoded. This data is authenticated but not encrypted. The same AAD must be provided during decryption.

* `mount_id` - (Required) The unique identifier for the Vault mount. This forces Terraform to wait until the mount
  is fully configured before performing encryption operations.

## Attributes Reference

The following attributes are exported:

* `ciphertext` - The base64-encoded encrypted ciphertext. This value can be stored and later decrypted using 
  the `vault_gcpkms_decrypt` ephemeral resource.
