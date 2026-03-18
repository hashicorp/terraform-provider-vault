---
layout: "vault"
page_title: "Vault: vault_keymgmt_gcp_kms resource"
sidebar_current: "docs-vault-resource-keymgmt-gcp-kms"
description: |-
  Manages GCP Cloud KMS provider in the Vault Key Management secrets engine
---

# vault\_keymgmt\_gcp\_kms

Manages a GCP Cloud KMS provider in the Vault Key Management secrets engine. This resource configures Vault to integrate with Google Cloud Platform's Key Management Service, allowing keys created in Vault to be distributed to GCP Cloud KMS for use in GCP services.

Once configured, keys can be distributed to GCP Cloud KMS using the `vault_keymgmt_distribute_key` resource.

For more information on managing GCP Cloud KMS with Vault, please refer to the Vault [documentation](https://developer.hashicorp.com/vault/docs/secrets/key-management).

**Note** this feature is available only with Vault Enterprise.

## Example Usage

### Using Explicit Credentials

```hcl
resource "vault_mount" "keymgmt" {
  path = "keymgmt"
  type = "keymgmt"
}

resource "vault_keymgmt_gcp_kms" "production" {
  mount          = vault_mount.keymgmt.path
  name           = "gcp-production"
  key_collection = "projects/my-project/locations/us-central1/keyRings/my-keyring"
  credentials_wo = {
    service_account_file = file("gcp-credentials.json")
    project              = "my-project"
    location             = "us-central1"
  }
  credentials_wo_version = 1
}
```

### Using GCP Application Default Credentials

```hcl
# When credentials_wo is not provided, Vault uses its own environment to
# authenticate with GCP. Supported options include:
# 1. The GOOGLE_APPLICATION_CREDENTIALS environment variable set on the Vault
#    server, pointing to a service account key file.
# 2. Application Default Credentials (ADC) when Vault runs on GCP infrastructure
#    with an attached service account.

resource "vault_mount" "keymgmt" {
  path = "keymgmt"
  type = "keymgmt"
}

resource "vault_keymgmt_gcp_kms" "production" {
  mount          = vault_mount.keymgmt.path
  name           = "gcp-production"
  key_collection = "projects/my-project/locations/us-central1/keyRings/my-keyring"

  # No credentials_wo - Vault authenticates using its own environment
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured
  [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required, Forces new resource) Path of the Key Management secrets engine mount. Must match the
  `path` of a [`vault_mount`](mount.html) resource with `type = "keymgmt"`. Use
  `vault_mount.keymgmt.path` here.

* `name` - (Required, Forces new resource) Specifies the name of the GCP Cloud KMS provider. Cannot be changed after creation.

* `key_collection` - (Required) Refers to a location to store keys in the GCP Cloud KMS provider. Cannot be changed after creation.

* `credentials_wo` - (Optional, Write-only, Sensitive) Map of GCP credentials passed directly to the Vault API.
  Supported keys are:
  - `service_account_file` - JSON-encoded GCP service account credentials with permissions to manage Cloud KMS keys.
  - `project` - GCP project ID where the Cloud KMS key ring is located.
  - `location` - GCP location/region for the Cloud KMS key ring.

  This field is write-only and will never be stored in Terraform state. If not provided, Vault uses credentials from its own environment (e.g. `GOOGLE_APPLICATION_CREDENTIALS` set on the Vault server, or GCP Application Default Credentials). Refer to the [Vault API docs](https://developer.hashicorp.com/vault/api-docs/secret/key-management#create-update-kms-provider) for the full list of accepted credential keys.

* `credentials_wo_version` - (Optional) Version counter for the write-only `credentials_wo` field. Since write-only values are not stored in state, Terraform cannot detect when credentials change. Increment this value whenever you update `credentials_wo` to ensure the new credentials are sent to Vault.

## Import

GCP Cloud KMS providers can be imported using the format `{path}/kms/{name}`, e.g.

```
$ terraform import vault_keymgmt_gcp_kms.production keymgmt/kms/gcp-production
```

~> **Note:** When importing, `credentials_wo` will not be populated as it is write-only and never returned by the Vault API. Set `credentials_wo` and `credentials_wo_version` after import to manage credentials.
