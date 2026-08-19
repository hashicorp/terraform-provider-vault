---
layout: "vault"
page_title: "Vault: ephemeral vault_azure_access_token resource"
sidebar_current: "docs-vault-ephemeral-azure-access-token"
description: |-
  Generate ephemeral Azure OAuth2 access tokens from Vault static role credentials

---

# vault\_azure\_access\_token (Ephemeral)

Generates ephemeral Azure OAuth2 access tokens from the Vault Azure Secrets Engine using static role credentials.
These tokens are not stored in Terraform state.

For more information, refer to
the [Vault Azure Secrets Engine documentation](https://developer.hashicorp.com/vault/docs/secrets/azure).

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
  mount    = vault_azure_secret_backend.azure.path
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

* `mount` - (Required) Path where the Azure Secrets Engine is mounted in Vault.

* `role` - (Required) Name of the Azure static role to generate an access token for.

* `scope` - (Required) The Azure OAuth2 scope to request the access token for
  (for example, `https://graph.microsoft.com/.default`).

* `max_retries` - (Optional) Maximum number of retries when waiting for the Azure AD
  credential to propagate. Defaults to `4`. Must be `0` or greater.

* `retry_delay` - (Optional) Number of seconds to wait between propagation retries.
  Defaults to `4`. Must be `0` or greater.

* `mount_id` - (Optional) If set, defers provisioning of the ephemeral resource until
  `terraform apply`. For more details, refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
  *Available only for Vault Enterprise*.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `access_token` - The Azure OAuth2 access token.

* `token_type` - The token type returned by Azure (for example, `Bearer`).

* `expires_in` - The access token lifetime in seconds.

* `ext_expires_in` - The extended access token lifetime in seconds, used by Azure for
  resilience in outage scenarios.

## Required Vault Capabilities

Use of this resource requires the following capabilities:

* `<mount>/token/<role>` - `update` (required on every call)
* `<mount>/static-creds/<role>` - `read` (required only on first use, to initialize the static credential)
