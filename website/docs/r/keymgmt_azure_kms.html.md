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

* `key_collection` - (Required, Forces new resource) Refers to a location to store keys in the Azure Key Vault provider. Cannot be changed after creation.

* `credentials_wo` - (Optional, Write-only, Sensitive) Map of Azure credentials passed directly to the Vault API.
  Supported keys are:
  - `tenant_id` - Azure Active Directory tenant ID (also called Directory ID).
  - `client_id` - Azure Active Directory application/client ID for the service principal.
  - `client_secret` - Azure Active Directory client secret for the service principal.
  - `environment` - (Optional) Azure cloud environment.

  This field is write-only and will never be stored in Terraform state. If not provided, Vault uses credentials from its own environment (e.g. `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` env vars set on the Vault server, or Azure Managed Identity). Refer to the [Vault API docs](https://developer.hashicorp.com/vault/api-docs/secret/key-management#create-update-kms-provider) for the full list of accepted credential keys.

* `credentials_wo_version` - (Optional) Version counter for the write-only `credentials_wo` field. Since write-only values are not stored in state, Terraform cannot detect when credentials change. Increment this value whenever you update `credentials_wo` to ensure the new credentials are sent to Vault.


## Import

Azure Key Vault providers can be imported using the format `{path}/kms/{name}`, e.g.

```
$ terraform import vault_keymgmt_azure_kms.production keymgmt/kms/azure-production
```

~> **Note:** When importing, `credentials_wo` will not be populated as it is write-only and never returned by the Vault API. Set `credentials_wo` and `credentials_wo_version` after import to manage credentials.
