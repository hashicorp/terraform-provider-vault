---
layout: "vault"
page_title: "Vault: vault_gcpkms_secret_sign ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-gcpkms-secret-sign"
description: |-
  Creates a digital signature using GCP KMS through Vault
---

# vault\_gcpkms\_sign

Creates a digital signature for a message digest using a GCP KMS signing key through Vault. This is an 
ephemeral resource that performs signing operations without storing the signature in state.

Ephemeral resources are ideal for cryptographic operations as they generate fresh signatures each time 
without persisting sensitive data.

## Example Usage

### Basic Signing

```hcl
resource "vault_gcpkms_secret_backend" "gcpkms" {
  path        = "gcpkms"
  credentials = file("gcp-credentials.json")
}

resource "vault_gcpkms_secret_backend_key" "signing_key" {
  backend          = vault_gcpkms_secret_backend.gcpkms.path
  name             = "signing-key"
  key_ring         = "projects/my-project/locations/us-central1/keyRings/my-keyring"
  purpose          = "asymmetric_sign"
  algorithm        = "rsa_sign_pss_2048_sha256"
  protection_level = "software"
}

locals {
  message = "important message to sign"
  digest  = base64encode(sha256(local.message))
}

ephemeral "vault_gcpkms_sign" "signature" {
  backend     = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = local.digest
  key_version = 1
  mount_id    = vault_gcpkms_secret_backend.gcpkms.id
}

output "signature" {
  value     = ephemeral.vault_gcpkms_sign.signature.signature
  sensitive = true
  ephemeral = true
}
```

### Signing with Specific Key Version

```hcl
ephemeral "vault_gcpkms_sign" "versioned" {
  backend     = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = base64encode(sha256("message"))
  key_version = 1
  mount_id    = vault_gcpkms_secret_backend.gcpkms.id
}
```

### Sign and Verify Workflow

```hcl
locals {
  message = "my important message"
  digest  = base64encode(sha256(local.message))
}

ephemeral "vault_gcpkms_sign" "create_signature" {
  backend     = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = local.digest
  key_version = 1
  mount_id    = vault_gcpkms_secret_backend.gcpkms.id
}

data "vault_gcpkms_verify" "check_signature" {
  backend     = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = local.digest
  signature   = ephemeral.vault_gcpkms_sign.create_signature.signature
  key_version = 1
}

# Will output: true
output "signature_valid" {
  value = data.vault_gcpkms_verify.check_signature.valid
}
```

### JWT Token Signing Example

```hcl
locals {
  jwt_header = jsonencode({
    alg = "RS256"
    typ = "JWT"
  })
  
  jwt_payload = jsonencode({
    sub  = "user123"
    name = "John Doe"
    iat  = 1516239022
    exp  = 1516242622
  })
  
  jwt_unsigned = "${base64encode(local.jwt_header)}.${base64encode(local.jwt_payload)}"
  jwt_digest   = base64encode(sha256(local.jwt_unsigned))
}

ephemeral "vault_gcpkms_sign" "jwt" {
  backend     = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = local.jwt_digest
  key_version = 1
  mount_id    = vault_gcpkms_secret_backend.gcpkms.id
}

output "signed_jwt" {
  value     = "${local.jwt_unsigned}.${ephemeral.vault_gcpkms_sign.jwt.signature}"
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

* `name` - (Required) Name of the signing key to use. This must reference a key with purpose `asymmetric_sign`.

* `digest` - (Required) Base64-encoded digest to sign. The digest must be created using the hash 
  algorithm that matches the key's algorithm (e.g., SHA-256 for `rsa_sign_pss_2048_sha256`).

* `key_version` - (Required) Specific version of the key to use for signing.

* `mount_id` - (Required) The unique identifier for the Vault mount. This forces Terraform to wait until the mount
  is fully configured before performing signing operations.

## Attributes Reference

The following attributes are exported:

* `signature` - The base64-encoded digital signature. This can be verified using the `vault_gcpkms_verify` 
  data source.

