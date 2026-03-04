---
layout: "vault"
page_title: "Vault: vault_gcpkms_encrypt ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-gcpkms-encrypt"
description: |-
  Encrypts plaintext using GCP KMS through Vault
---

# vault\_gcpkms\_encrypt

Encrypts plaintext data using a GCP KMS encryption key through Vault. This is an ephemeral resource that
performs encryption operations without storing the resulting ciphertext in Terraform state.

## Example Usage

### Basic Encryption

```hcl
resource "vault_gcpkms_secret_backend" "gcpkms" {
  path                   = "gcpkms"
  credentials_wo         = file("gcp-credentials.json")
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "encryption_key" {
  mount            = vault_gcpkms_secret_backend.gcpkms.path
  name             = "my-key"
  key_ring         = "projects/my-project/locations/us-central1/keyRings/my-keyring"
  purpose          = "encrypt_decrypt"
  algorithm        = "symmetric_encryption"
  protection_level = "software"
}

ephemeral "vault_gcpkms_encrypt" "data" {
  mount_id  = tostring(vault_gcpkms_secret_backend_key.encryption_key.latest_version)
  mount     = vault_gcpkms_secret_backend.gcpkms.path
  name      = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext = base64encode("sensitive data to encrypt")
}

resource "aws_ssm_parameter" "encrypted_secret" {
  name  = "/myapp/encrypted-data"
  type  = "String"
  value = ephemeral.vault_gcpkms_encrypt.data.ciphertext
}
```

### Encryption with Additional Authenticated Data (AAD)

```hcl
ephemeral "vault_gcpkms_encrypt" "with_aad" {
  mount_id                      = tostring(vault_gcpkms_secret_backend_key.encryption_key.latest_version)
  mount                         = vault_gcpkms_secret_backend.gcpkms.path
  name                          = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext                     = base64encode("sensitive data")
  additional_authenticated_data = base64encode("context-info")
}
```

### Encryption with Specific Key Version

```hcl
ephemeral "vault_gcpkms_encrypt" "versioned" {
  mount_id    = tostring(vault_gcpkms_secret_backend_key.encryption_key.latest_version)
  mount       = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext   = base64encode("sensitive data")
  key_version = 2
}
```

### Encrypt-Decrypt Workflow

```hcl
ephemeral "vault_gcpkms_encrypt" "secret" {
  mount_id  = tostring(vault_gcpkms_secret_backend_key.encryption_key.latest_version)
  mount     = vault_gcpkms_secret_backend.gcpkms.path
  name      = vault_gcpkms_secret_backend_key.encryption_key.name
  plaintext = base64encode("my secret message")
}

ephemeral "vault_gcpkms_decrypt" "recovered" {
  mount      = vault_gcpkms_secret_backend.gcpkms.path
  name       = vault_gcpkms_secret_backend_key.encryption_key.name
  ciphertext = ephemeral.vault_gcpkms_encrypt.secret.ciphertext
}

output "decrypted_value" {
  value     = ephemeral.vault_gcpkms_decrypt.recovered.plaintext
  sensitive = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured
  [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount_id` - (Optional) Terraform ID of the mount resource. Used to defer the provisioning of the
  ephemeral resource until the apply stage, after the GCP KMS secrets engine mount and key have been
  created. Set this to `tostring(vault_gcpkms_secret_backend_key.<name>.latest_version)` to establish
  the correct dependency ordering.

* `mount` - (Required) Path where the GCP KMS secrets engine is mounted.

* `name` - (Required) Name of the encryption key to use. The key must have purpose `encrypt_decrypt`.

* `plaintext` - (Required, Sensitive) Base64-encoded plaintext data to encrypt.

* `additional_authenticated_data` - (Optional) Base64-encoded additional authenticated data (AAD) to
  include in the encryption. This data is authenticated but not encrypted. The same AAD must be
  provided during decryption.

* `key_version` - (Optional) Specific version of the key to use for encryption. If not specified, the
  key's primary version will be used.

## Attributes Reference

The following attributes are exported:

* `ciphertext` - The base64-encoded encrypted ciphertext. This value can be later decrypted using
  the [`vault_gcpkms_decrypt`](/docs/providers/vault/ephemeral-resources/gcpkms_secret_decrypt.html)
  ephemeral resource.
