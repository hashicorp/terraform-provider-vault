---
layout: "vault"
page_title: "Vault: ephemeral vault_azure_static_credentials data resource"
sidebar_current: "docs-vault-ephemeral-azure-static-credentials"
description: |-
  Read an ephemeral static secret from the Vault Azure Secrets engine

---

# vault_azure_access_static_credentials (Ephemeral)

Reads ephemeral static Azure credentials for a static role managed by the Azure Secrets Engine.  
These credentials are not stored in Terraform state.

For more information, refer to the [Vault Azure Secrets Engine documentation](https://developer.hashicorp.com/vault/docs/secrets/azure).

## Example Usage

```hcl
resource "vault_azure_secret_backend" "azure" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
  client_secret   = var.client_secret
  client_id       = var.client_id
}

resource "vault_azure_secret_backend_static_role" "example" {
  backend              = vault_azure_secret_backend.azure.path
  role                 = "example-role"
  application_object_id = "00000000-0000-0000-0000-000000000000"
}

ephemeral "vault_azure_static_credentials" "creds" {
  backend = vault_azure_secret_backend.azure.path
  role    = vault_azure_secret_backend_static_role.example.role
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) Path to the mounted Azure Secrets Engine where the static role resides.

* `role` - (Required) The name of the static role to generate or read credentials for.

* `metadata` - (Optional) A map of key-value pairs to associate with the static role and include in the credential response.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `client_id` - The Azure AD Application’s client ID associated with this static role.

* `client_secret` - The managed client secret value for the application.

* `secret_id` - The Azure Key ID corresponding to the current client secret.

* `expiration` - The expiration timestamp (in RFC3339 format) of the credential, as reported by Azure.