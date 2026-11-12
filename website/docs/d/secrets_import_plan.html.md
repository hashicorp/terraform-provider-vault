---
layout: "vault"
page_title: "Vault: vault_secrets_import_plan data source"
sidebar_current: "docs-vault-datasource-secrets-import-plan"
description: |-
  Previews which secrets a secrets import source would import.
---

# vault\_secrets\_import\_plan

Previews a secrets import source ([AWS](../r/secrets_import_aws_source.html),
[GCP](../r/secrets_import_gcp_source.html) or [Azure](../r/secrets_import_azure_source.html)): Vault lists the
selected cloud secrets and reports which destination paths would be imported, without
reading secret values or writing anything. The preview runs on every refresh, so it shows
up in `terraform plan`. Use [`vault_secrets_import_apply`](../r/secrets_import_apply.html)
to run the import.
*Available only for Vault Enterprise*.

~> **Experimental** This data source targets the proof-of-concept
`GET sys/import/sources/:type/:name/plan` API.

## Example Usage

```hcl
data "vault_secrets_import_plan" "aws" {
  type = "aws-sm"
  name = vault_secrets_import_aws_source.prod.name
}

output "would_import" {
  value = data.vault_secrets_import_plan.aws.would_import
}
```

## Argument Reference

The following arguments are supported:

* `type` - (Required) Type of the import source: `aws-sm`, `azure-kv` or `gcp-sm`.

* `name` - (Required) Name of the import source to preview.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `auth_mode` - How Vault authenticated to the cloud provider.

* `destination_mount` - KV v2 mount the secrets would be imported into.

* `scanned_count` - Number of secrets found in the source.

* `would_import` - Destination paths of the secrets that would be imported.

* `would_import_count` - Number of secrets that would be imported.

* `ignored` - Source secrets not selected by the source's filter.

* `failed` - Map of destination paths that could not be planned to the error.

* `failed_count` - Number of secrets that could not be planned.
