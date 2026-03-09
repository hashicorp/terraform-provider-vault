---
layout: "vault"
page_title: "Vault: vault_gcpkms_verify data source"
sidebar_current: "docs-vault-datasource-gcpkms-verify"
description: |-
  Verifies a digital signature using GCP KMS
---

# vault\_gcpkms\_verify

Verifies a digital signature against a digest using a GCP KMS signing key through Vault. This data source 
performs read-only signature verification operations.

## Example Usage

### Basic Signature Verification

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

resource "vault_gcpkms_secret_backend_key" "signing_key" {
  mount     = vault_mount.gcpkms.path
  name      = "signing-key"
  key_ring  = "projects/my-project/locations/us-central1/keyRings/my-keyring"
  purpose   = "asymmetric_sign"
  algorithm = "rsa_sign_pss_2048_sha256"
}

data "vault_gcpkms_verify" "signature_check" {
  mount       = vault_mount.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = base64encode("my message digest")
  signature   = "BASE64_ENCODED_SIGNATURE"
  key_version = 1
}

output "signature_is_valid" {
  value = data.vault_gcpkms_verify.signature_check.valid
}
```

### Using with Ephemeral Sign Resource

```hcl
ephemeral "vault_gcpkms_sign" "create_signature" {
  mount_id    = vault_mount.gcpkms.id
  mount       = vault_mount.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = base64encode("my message digest")
  key_version = 1
}

data "vault_gcpkms_verify" "verify_signature" {
  mount       = vault_mount.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = base64encode("my message digest")
  signature   = ephemeral.vault_gcpkms_sign.create_signature.signature
  key_version = 1
}

# Will output: true
output "signature_valid" {
  value = data.vault_gcpkms_verify.verify_signature.valid
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured
  [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where the GCP KMS secrets engine is mounted.

* `name` - (Required) Name of the signing key to use for verification. This must reference a key with 
  purpose `ASYMMETRIC_SIGN`.

* `digest` - (Required) Base64-encoded digest to verify. The digest should be created using the hash algorithm
  specified in the key's algorithm (e.g., SHA256 for RSA_SIGN_PSS_2048_SHA256).

* `signature` - (Required) Base64-encoded signature to verify against the digest.

* `key_version` - (Required) Specific version of the key to use for verification. If not specified, Vault 
  will use the key's primary version.

## Attributes Reference

The following attributes are exported:

* `valid` - Boolean indicating whether the signature is valid (`true`) or invalid (`false`).
