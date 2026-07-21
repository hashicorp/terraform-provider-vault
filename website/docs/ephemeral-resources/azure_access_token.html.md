---
layout: "vault"
page_title: "Vault: ephemeral vault_azure_access_token resource"
sidebar_current: "docs-vault-ephemeral-azure-access-token"
description: |-
  Generate ephemeral Azure OAuth2 access tokens from Vault static role credentials

---

# vault_azure_access_token

Generates ephemeral Azure OAuth2 access tokens from the Vault Azure Secrets engine using static role credentials.
The token is not stored in Terraform state.

For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/docs/secrets/azure)
for the Azure Secrets engine.

## Example Usage

```hcl
resource "vault_azure_secret_backend" "azure" {
  path            = "azure"
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
  client_id       = var.client_id
  client_secret   = var.client_secret
}

resource "vault_azure_secret_backend_static_role" "role" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "my-app"
  application_object_id = var.application_object_id
  ttl                   = 31536000
}

ephemeral "vault_azure_access_token" "token" {
  mount_id = vault_azure_secret_backend_static_role.role.id
  backend  = vault_azure_secret_backend.azure.path
  role     = vault_azure_secret_backend_static_role.role.role
  scope    = "https://graph.microsoft.com/.default"
}

output "access_token" {
  value     = ephemeral.vault_azure_access_token.token.access_token
  sensitive = true
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) Path where the Azure secrets engine is mounted in Vault.

* `role` - (Required) Name of the Azure static role to generate an access token for.

* `scope` - (Required) The full Azure scope to request a token for (for example, `https://graph.microsoft.com/.default`).

* `mount_id` - (Optional) If value is set, will defer provisioning the ephemeral resource until
  `terraform apply`. For more details, please refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
  *Available only for Vault Enterprise*.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `access_token` - The Azure OAuth2 access token.

* `token_type` - The token type returned by Azure (for example, `Bearer`).

* `expires_in` - The token lifetime in seconds.

* `ext_expires_in` - The extended token lifetime in seconds.

## Required Vault Capabilities

Use of this resource requires the `read` capability on both the backend config path and static credentials path:

* `<backend>/config`
* `<backend>/static-creds/<role>`
