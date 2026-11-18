---
layout: "vault"
page_title: "Vault: vault_secrets_import_azure_source resource"
sidebar_current: "docs-vault-resource-secrets-import-azure-source"
description: |-
  Manages a secrets import source that imports Azure Key Vault secrets into a KV v2 mount.
---

# vault\_secrets\_import\_azure\_source

Manages an Azure Key Vault secrets import source. A source describes which Azure Key Vault to read,
how Vault authenticates to it, and the KV v2 mount the secrets are imported into. Use the
[`vault_secrets_import_plan`](../d/secrets_import_plan.html) data source to preview an
import and [`vault_secrets_import_apply`](secrets_import_apply.html) to run it, both with
`type = "azure-kv"`.
*Available only for Vault Enterprise*. Sources are only supported in the root namespace.

Vault picks the authentication mode from the arguments that are set:

* `identity_token_audience`, `tenant_id` and `client_id` - workload identity federation (WIF).
* `client_secret`, `tenant_id` and `client_id` - static client secret.
* None of these - the Vault server's host credentials (for example a managed identity).

~> **Experimental** This resource targets the proof-of-concept
`sys/import/sources/azure-kv/:name` API.

~> **Important** Static credentials are a fallback for environments without host
credentials or WIF. Vault accepts them with a warning. They are stored in Terraform state,
so protect the state accordingly.

## Example Usage

```hcl
resource "vault_secrets_import_azure_source" "prod" {
  name                    = "azure-prod"
  key_vault_uri           = "https://my-vault.vault.azure.net"
  tenant_id               = "00000000-0000-0000-0000-000000000000"
  client_id               = "11111111-1111-1111-1111-111111111111"
  identity_token_audience = "api://AzureADTokenExchange"
  destination_mount       = vault_mount.kvv2.path
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Unique name of the source within its type. Changing this forces a new resource.

* `destination_mount` - (Required) Path of the KV v2 mount secrets are imported into.

* `filter` - (Optional) [go-bexpr](https://github.com/hashicorp/go-bexpr) filter
  selecting which source secrets to import.

* `identity_token_audience` - (Optional) Audience expected by the cloud provider's
  identity federation. When set, Vault uses workload identity federation (WIF). Requires `tenant_id` and `client_id`.

* `identity_token_key` - (Optional) Identity token key used to sign the workload identity token.
  Requires `identity_token_audience`.

* `identity_token_ttl` - (Optional) TTL of the workload identity token, in seconds.
  Requires `identity_token_audience`.

Azure:

* `key_vault_uri` - (Required) URI of the Key Vault to import secrets from.

* `tenant_id` - (Optional) Tenant ID. Required with `identity_token_audience` or `client_secret`.

* `client_id` - (Optional) Client ID of the app registration or user-assigned managed
  identity. Required with `identity_token_audience` or `client_secret`.

* `client_secret` - (Optional, Sensitive) Static client secret. Requires `tenant_id` and
  `client_id`. Conflicts with `identity_token_audience`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `auth_mode` - How Vault authenticates to the cloud provider: `host_credentials`, `static_credentials` or `workload_identity_federation`.

* `created_at` - Time the source was created.

* `updated_at` - Time the source was last updated.

## Import

Azure sources can be imported using the `name`, e.g.

```
$ terraform import vault_secrets_import_azure_source.example azure-prod
```

Static credentials are masked by Vault and are not read back, so they are empty after
import. Set them in the configuration again.
