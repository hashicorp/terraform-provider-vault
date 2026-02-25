---
layout: "vault"
page_title: "Vault: vault_gcpkms_secret_backend resource"
sidebar_current: "docs-vault-resource-gcpkms-secret-backend"
description: |-
  Manages the GCP KMS secrets engine in Vault
---

# vault\_gcpkms\_secret\_backend

Manages the GCP KMS secrets engine in Vault. The GCP KMS secrets engine provides encryption and decryption 
services backed by Google Cloud Platform's Key Management Service (KMS). This allows you to use GCP KMS keys 
for cryptographic operations through Vault.

~> **Important** This resource requires **Terraform 1.11+** for write-only attribute support.
The `credentials_wo` field is write-only and will never be stored in Terraform state.
See [the main provider documentation](../index.html)
for more details.

## Example Usage

### Basic Configuration

```hcl
resource "vault_gcpkms_secret_backend" "gcpkms" {
  path                   = "gcpkms"
  credentials_wo         = file("gcp-credentials.json")
  credentials_wo_version = 1
}
```

### With Custom Scopes

```hcl
resource "vault_gcpkms_secret_backend" "gcpkms" {
  path                   = "gcpkms"
  credentials_wo         = file("gcp-credentials.json")
  credentials_wo_version = 1
  scopes = [
    "https://www.googleapis.com/auth/cloudkms",
    "https://www.googleapis.com/auth/cloud-platform"
  ]
}
```

### Rotating Credentials

To rotate credentials, update the `credentials_wo` value and increment `credentials_wo_version`.
The version change signals to Terraform that the credentials should be re-sent to Vault.

```hcl
resource "vault_gcpkms_secret_backend" "gcpkms" {
  path                   = "gcpkms"
  credentials_wo         = file("gcp-credentials-new.json")
  credentials_wo_version = 2
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Required) Path where the GCP KMS secrets engine will be mounted. This path cannot be changed after creation.

* `credentials_wo_version` - (Required) Version number for the write-only credentials. Increment this
  value to trigger a credential rotation. Changing this value will cause the credentials to be re-sent
  to Vault during the next apply. For more info see
  [updating write-only attributes](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_write_only_attributes.html#updating-write-only-attributes).

* `scopes` - (Optional) Set of OAuth scopes to use for GCP API requests. Defaults to `["https://www.googleapis.com/auth/cloudkms"]`.
  Common scopes include:
  - `https://www.googleapis.com/auth/cloudkms` - Cloud KMS access
  - `https://www.googleapis.com/auth/cloud-platform` - Full cloud platform access

## Ephemeral Attributes Reference

The following write-only attributes are supported:

* `credentials_wo` - (Required) JSON-encoded GCP service account credentials. This value is write-only
  and will not be stored in Terraform state. The credentials should have the
  `cloudkms.cryptoKeyVersions.useToEncrypt`, `cloudkms.cryptoKeyVersions.useToDecrypt`, and
  `cloudkms.cryptoKeys.get` permissions at minimum.
  **Note**: This property is write-only and will not be read from the API. Requires Terraform 1.11+.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The path where the GCP KMS secrets engine is mounted.

## Import

GCP KMS secrets engines can be imported using the `path`, e.g.

```
$ terraform import vault_gcpkms_secret_backend.gcpkms gcpkms
```

~> **Note:** When importing, the `credentials_wo` and `credentials_wo_version` fields will not be
populated as they are not returned by the Vault API. You must supply these values in your configuration
after import.

## Required GCP Permissions

The service account credentials provided must have the following IAM permissions:

- `cloudkms.cryptoKeyVersions.useToEncrypt` - For encryption operations
- `cloudkms.cryptoKeyVersions.useToDecrypt` - For decryption operations  
- `cloudkms.cryptoKeyVersions.useToSign` - For signing operations
- `cloudkms.cryptoKeyVersions.get` - For reading key version information
- `cloudkms.cryptoKeys.get` - For reading key information
- `cloudkms.cryptoKeys.create` - For creating new keys (optional)

These permissions are typically granted through the `Cloud KMS CryptoKey Encrypter/Decrypter` and 
`Cloud KMS Viewer` IAM roles.
