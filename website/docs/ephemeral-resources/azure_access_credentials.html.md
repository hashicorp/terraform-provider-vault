---
layout: "vault"
page_title: "Vault: ephemeral vault_azure_access_credentials resource"
sidebar_current: "docs-vault-ephemeral-azure-access-credentials"
description: |-
  Read an ephemeral dynamic secret from the Vault Azure Secrets engine

---

# vault_azure_access_credentials (Ephemeral)

Reads ephemeral dynamic Azure credentials for a role managed by the Azure Secrets Engine.  
These credentials are not stored in Terraform state.

For more information, refer to
the [Vault Azure Secrets Engine documentation](https://developer.hashicorp.com/vault/docs/secrets/azure).

## Example Usage

```hcl
resource "vault_azure_secret_backend" "azure" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
  client_id       = var.client_id
  client_secret   = var.client_secret
  path            = "azure"
}

resource "vault_azure_secret_backend_role" "azurerole" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "azurerole"
  ttl                   = 3600
  max_ttl               = 7200
  application_object_id = "00000000-0000-0000-0000-000000000000"
}

ephemeral "vault_azure_access_credentials" "creds" {
  mount_id = vault_azure_secret_backend.azure.id
  backend  = vault_azure_secret_backend.azure.path
  role     = vault_azure_secret_backend_role.azurerole.role
}
```

## Argument Reference

The following arguments are supported:

* `mount_id` - (Optional) If value is set, will defer provisioning the ephemeral resource until
  `terraform apply`. For more details, please refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) Path to the mounted Azure Secrets Engine where the role resides.

* `role` - (Required) The name of the Azure role to generate credentials for.

* `validate_creds` - (Optional) Whether generated credentials should be validated before being returned.

* `num_sequential_successes` - (Optional) If 'validate_creds' is true, the number of sequential successes required to validate generated credentials. Defaults to 4.

* `num_seconds_between_tests` - (Optional) If 'validate_creds' is true, the number of seconds to wait between each test of generated credentials. Defaults to 1.

* `max_cred_validation_seconds` - (Optional) If 'validate_creds' is true, the number of seconds after which to give up validating credentials. Defaults to 300.

* `subscription_id` - (Optional) The subscription ID to use during credential validation. Defaults to the subscription ID configured in the Vault backend.

* `tenant_id` - (Optional) The tenant ID to use during credential validation. Defaults to the tenant ID configured in the Vault backend.

* `environment` - (Optional) The Azure environment to use during credential validation. Defaults to the Azure Public Cloud. Some possible values: AzurePublicCloud, AzureUSGovernmentCloud.

* `request_metadata` - (Optional) Request-time map of key-value pairs to associate with the static role and include in the credential response.
  These key-value pairs are merged with the role's configured metadata.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `client_id` - The Azure AD Application's client ID.

* `client_secret` - The client secret for the Azure AD Application.

* `lease_id` - The lease identifier assigned by Vault.

* `lease_duration` - The duration of the secret lease in seconds.

* `lease_start_time` - The time when the lease was read, in RFC3339 format.

* `lease_renewable` - True if the lease can be renewed.

* `metadata` - Computed map of key-value pairs that combines the role's metadata with the metadata
  sent in the request. If a key exists in both, the value from the role's metadata takes precedence.
