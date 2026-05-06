---
layout: "vault"
page_title: "Vault: vault_keymgmt_azure_kms resource"
sidebar_current: "docs-vault-resource-keymgmt-azure-kms"
description: |-
  Manages Azure Key Vault provider in the Vault Key Management secrets engine
---

# vault\_keymgmt\_azure\_kms

Manages an Azure Key Vault provider in the Vault Key Management secrets engine. This resource configures Vault to integrate with Azure Key Vault, allowing keys created in Vault to be distributed to Azure Key Vault for use in Azure services.

Once configured, keys can be distributed to Azure Key Vault using the `vault_keymgmt_distribute_key` resource.

~> **Important** This resource requires **Terraform 1.11+** for write-only attribute support.
The `credentials_wo` field is write-only and will never be stored in Terraform state.
See [the main provider documentation](../index.html) for more details.

For more information on managing Azure Key Vault with Vault, please refer to the Vault [documentation](https://developer.hashicorp.com/vault/docs/secrets/key-management).

**Note** this feature is available only with Vault Enterprise.

## Example Usage

### Using Explicit Credentials

```hcl
resource "vault_mount" "keymgmt" {
  path = "keymgmt"
  type = "keymgmt"
}

resource "vault_keymgmt_azure_kms" "production" {
  mount          = vault_mount.keymgmt.path
  name           = "azure-production"
  key_collection = "my-keyvault"
  credentials_wo = {
    tenant_id     = var.azure_tenant_id
    client_id     = var.azure_client_id
    client_secret = var.azure_client_secret
    environment   = "AzurePublicCloud"
  }
  credentials_wo_version = 1
}
```

### Using Azure Environment Variables or Managed Identity

```hcl
# When credentials_wo is not provided, Vault uses its own environment to
# authenticate with Azure. Supported options include:
# 1. Environment variables set on the Vault server:
#    AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
# 2. Azure Managed Identity (when Vault runs on an Azure VM or service
#    with an assigned identity)

resource "vault_mount" "keymgmt" {
  path = "keymgmt"
  type = "keymgmt"
}

resource "vault_keymgmt_azure_kms" "production" {
  mount          = vault_mount.keymgmt.path
  name           = "azure-production"
  key_collection = "my-keyvault"

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

* `name` - (Required, Forces new resource) Specifies the name of the Azure Key Vault provider. Cannot be changed after creation.

* `key_collection` - (Required, Forces new resource) Refers to the name of an existing Azure Key Vault instance. Cannot be changed after creation.

* `credentials_wo` - (Optional, Write-only, Sensitive) The credentials to use for authentication with Azure Key Vault. Supplying values for this parameter is optional, as credentials may also be specified as environment variables. Environment variables will take precedence over credentials provided via this parameter. This value is write-only and will not be stored in Terraform state.
  The following values are supported:
  - `tenant_id` - (Required) The tenant ID for the Azure Active Directory organization. May also be specified by the AZURE_TENANT_ID environment variable.
  - `client_id` - (Required) The client ID for credentials to invoke the Azure APIs. May also be specified by the AZURE_CLIENT_ID environment variable.
  - `client_secret` - (Required) The client secret for credentials to invoke the Azure APIs. May also be specified by the AZURE_CLIENT_SECRET environment variable.
  - `environment` - (Optional) The Azure Cloud environment API endpoints to use. May also be specified by the AZURE_ENVIRONMENT environment variable. Defaults to `AzurePublicCloud`.

* `credentials_wo_version` - (Optional) Version number for the write-only credentials. Increment this value to trigger a credential rotation. Changing this value will cause the credentials to be re-sent to Vault during the next apply. For more info see [updating write-only attributes](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_write_only_attributes.html#updating-write-only-attributes).


## Import

Azure Key Vault providers can be imported using the format `{path}/kms/{name}`, e.g.

```
$ terraform import vault_keymgmt_azure_kms.production keymgmt/kms/azure-production
```

> **Note:** Import sets the `mount` attribute from the import ID. The `credentials_wo` and `credentials_wo_version` fields will not be populated as they are not returned by the Vault API. You must supply these values in your configuration after import. The corresponding `vault_mount` resource must also be present in your configuration (or separately imported).
