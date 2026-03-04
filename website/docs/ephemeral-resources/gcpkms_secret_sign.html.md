---
layout: "vault"
page_title: "Vault: vault_gcpkms_sign ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-gcpkms-sign"
description: |-
  Creates a digital signature using GCP KMS through Vault
---

# vault\_gcpkms\_sign

Creates a digital signature for a message digest using a GCP KMS asymmetric signing key through Vault.
This is an ephemeral resource that performs signing operations without storing the signature in Terraform
state.

## Example Usage

### Basic Signing

```hcl
resource "vault_gcpkms_secret_backend" "gcpkms" {
  path                   = "gcpkms"
  credentials_wo         = file("gcp-credentials.json")
  credentials_wo_version = 1
}

resource "vault_gcpkms_secret_backend_key" "signing_key" {
  mount            = vault_gcpkms_secret_backend.gcpkms.path
  name             = "signing-key"
  key_ring         = "projects/my-project/locations/us-central1/keyRings/my-keyring"
  purpose          = "asymmetric_sign"
  algorithm        = "ec_sign_p256_sha256"
  protection_level = "software"
}

locals {
  message = "important message to sign"
  digest  = base64encode(sha256(local.message))
}

ephemeral "vault_gcpkms_sign" "signature" {
  mount_id    = tostring(vault_gcpkms_secret_backend_key.signing_key.latest_version)
  mount       = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = local.digest
  key_version = 1
}

# Ephemeral values cannot be used in output blocks — use a check block instead.
check "signature_produced" {
  assert {
    condition     = length(ephemeral.vault_gcpkms_sign.signature.signature) > 0
    error_message = "Signing did not produce a signature"
  }
}
```

### Sign and Verify Workflow

Sign a digest during apply, then verify it in a subsequent plan using
`vault_gcpkms_verify`. Because `vault_gcpkms_verify` is a data source (runs
at plan time), it cannot directly reference an ephemeral output. Capture the
signature via `local_sensitive_file` or pass it in as a variable on the next
run.

```hcl
locals {
  message = "my important message"
  digest  = base64encode(sha256(local.message))
}

ephemeral "vault_gcpkms_sign" "create_signature" {
  mount_id    = tostring(vault_gcpkms_secret_backend_key.signing_key.latest_version)
  mount       = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = local.digest
  key_version = 1
}

# Write signature to a local file so it can be read back on the next plan.
resource "local_sensitive_file" "signature" {
  filename = "${path.module}/signature.b64"
  content  = ephemeral.vault_gcpkms_sign.create_signature.signature
}

# On a subsequent plan, verify using the captured signature file.
data "vault_gcpkms_verify" "check_signature" {
  mount       = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.signing_key.name
  digest      = local.digest
  signature   = trimspace(file("${path.module}/signature.b64"))
  key_version = 1
}

output "signature_valid" {
  value = data.vault_gcpkms_verify.check_signature.valid
}
```

### JWT Token Signing

Signs a JWT header+payload digest using a GCP KMS EC P-256 key. The resulting
signature can be appended to form a complete ES256 JWT.

```hcl
locals {
  jwt_header  = base64encode(jsonencode({ alg = "ES256", typ = "JWT" }))
  jwt_payload = base64encode(jsonencode({
    sub = "user-123"
    iss = "my-service"
    iat = 1700000000
    exp = 1700003600
  }))

  # JWT signing input is "header.payload"; digest is its SHA-256
  jwt_signing_input = "${local.jwt_header}.${local.jwt_payload}"
  jwt_digest        = base64encode(sha256(local.jwt_signing_input))
}

resource "vault_gcpkms_secret_backend_key" "jwt_key" {
  mount            = vault_gcpkms_secret_backend.gcpkms.path
  name             = "jwt-signing-key"
  key_ring         = "projects/my-project/locations/us-central1/keyRings/my-keyring"
  purpose          = "asymmetric_sign"
  algorithm        = "ec_sign_p256_sha256"
  protection_level = "software"
}

ephemeral "vault_gcpkms_sign" "jwt_signature" {
  mount_id    = tostring(vault_gcpkms_secret_backend_key.jwt_key.latest_version)
  mount       = vault_gcpkms_secret_backend.gcpkms.path
  name        = vault_gcpkms_secret_backend_key.jwt_key.name
  digest      = local.jwt_digest
  key_version = 1
}

check "jwt_signature_produced" {
  assert {
    condition     = length(ephemeral.vault_gcpkms_sign.jwt_signature.signature) > 0
    error_message = "JWT signing did not produce a signature"
  }
}

# The assembled JWT is: "${local.jwt_signing_input}.${signature}"
# Reference ephemeral.vault_gcpkms_sign.jwt_signature.signature directly
# in any resource that consumes it within the same apply, e.g.:
#
#   resource "local_sensitive_file" "jwt" {
#     filename = "${path.module}/token.jwt"
#     content  = "${local.jwt_signing_input}.${ephemeral.vault_gcpkms_sign.jwt_signature.signature}"
#   }
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

* `name` - (Required) Name of the signing key to use. The key must have purpose `asymmetric_sign`.

* `digest` - (Required) Base64-encoded digest of the message to sign. The digest algorithm must match
  the key's configured algorithm (e.g., SHA-256 for `ec_sign_p256_sha256`).

* `key_version` - (Required) Version of the key to use for signing.

## Attributes Reference

The following attributes are exported:

* `signature` - The base64-encoded digital signature. This can be verified using the
  [`vault_gcpkms_verify`](/docs/providers/vault/d/gcpkms_verify.html) data source.

