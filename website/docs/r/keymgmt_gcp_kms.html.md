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

~> **Important** This resource requires **Terraform 1.11+** for write-only attribute support.
The `credentials_wo` field is write-only and will never be stored in Terraform state.
See [the main provider documentation](../index.html) for more details.

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

* `key_collection` - (Required, Forces new resource) Refers to the resource ID of an existing GCP Cloud KMS key ring. Cannot be changed after creation.

* `credentials_wo` - (Optional, Write-only, Sensitive) The credentials to use for authentication with Google Cloud KMS. Supplying values for this parameter is optional, as credentials may also be specified through environment variables (GOOGLE_CREDENTIALS) or Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS). The order of precedence is: environment variables, then the credentials provided to this parameter and Application Default Credentials. This value is write-only and will not be stored in Terraform state.
  The following values are supported:
  - `service_account_file` - (Required) The path to a Google service account key file. The key file must be readable on the host that Vault server is running on. May also be provided by the GOOGLE_CREDENTIALS environment variable or by application default credentials.

* `credentials_wo_version` - (Optional) Version number for the write-only credentials. Increment this value to trigger a credential rotation. Changing this value will cause the credentials to be re-sent to Vault during the next apply. For more info see [updating write-only attributes](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_write_only_attributes.html#updating-write-only-attributes).

## Import

GCP Cloud KMS providers can be imported using the format `{path}/kms/{name}`, e.g.

```
$ terraform import vault_keymgmt_gcp_kms.production keymgmt/kms/gcp-production
```

> **Note:** Import sets the `mount` attribute from the import ID. The `credentials_wo` and `credentials_wo_version` fields will not be populated as they are not returned by the Vault API. You must supply these values in your configuration after import. The corresponding `vault_mount` resource must also be present in your configuration (or separately imported).
