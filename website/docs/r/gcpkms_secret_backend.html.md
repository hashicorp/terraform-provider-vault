---
layout: "vault"
page_title: "Vault: vault_gcpkms_secret_backend resource"
sidebar_current: "docs-vault-resource-gcpkms-secret-backend"
description: |-
  Manages the GCP KMS secrets engine in Vault
---

# vault\_gcpkms\_secret\_backend

Configures the GCP KMS secrets engine credentials and scopes in Vault. This resource **only manages
the `<mount>/config` endpoint** — credentials and OAuth scopes. The mount itself must be created
separately using a [`vault_mount`](mount.html) resource with `type = "gcpkms"`.

~> **Important** This resource requires **Terraform 1.11+** for write-only attribute support.
The `credentials_wo` field is write-only and will never be stored in Terraform state.
See [the main provider documentation](../index.html) for more details.

## Example Usage

### Basic Configuration

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
```

### With Custom Scopes

```hcl
resource "vault_mount" "gcpkms" {
  path = "gcpkms"
  type = "gcpkms"
}

resource "vault_gcpkms_secret_backend" "gcpkms" {
  mount                  = vault_mount.gcpkms.path
  credentials_wo         = file("gcp-credentials.json")
  credentials_wo_version = 1
  scopes = [
    "https://www.googleapis.com/auth/cloudkms",
    "https://www.googleapis.com/auth/cloud-platform"
  ]
}
```

### Rotating Credentials

To rotate credentials, update `credentials_wo` and increment `credentials_wo_version`.
The version change signals to Terraform that the new credentials should be sent to Vault.

```hcl
resource "vault_mount" "gcpkms" {
  path = "gcpkms"
  type = "gcpkms"
}

resource "vault_gcpkms_secret_backend" "gcpkms" {
  mount                  = vault_mount.gcpkms.path
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

* `mount` - (Required, Forces new resource) Path of the GCP KMS secrets engine mount. Must match the
  `path` of a [`vault_mount`](mount.html) resource with `type = "gcpkms"`. Use
  `vault_mount.<name>.path` here.

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

No additional attributes are exported beyond the arguments above.

## Import

GCP KMS backend configurations can be imported using the mount path, e.g.

```
$ terraform import vault_gcpkms_secret_backend.gcpkms gcpkms
```

~> **Note:** Import sets the `mount` attribute from the import ID. The `credentials_wo` and
`credentials_wo_version` fields will not be populated as they are not returned by the Vault API.
You must supply these values in your configuration after import. The corresponding `vault_mount`
resource must also be present in your configuration (or separately imported).

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
