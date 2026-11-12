---
layout: "vault"
page_title: "Vault: vault_secrets_import_apply resource"
sidebar_current: "docs-vault-resource-secrets-import-apply"
description: |-
  Applies a secrets import source and records the result.
---

# vault\_secrets\_import\_apply

Applies a secrets import source ([AWS](secrets_import_aws_source.html),
[GCP](secrets_import_gcp_source.html) or [Azure](secrets_import_azure_source.html)) once when
the resource is created: Vault reads the selected cloud secrets and writes them to the
destination KV v2 mount. The result is recorded in state. Changing `type`, `name` or any value
in `triggers` replaces the resource, which applies the source again. Destroying the resource only removes it from
state; secrets that were already imported stay in Vault.
*Available only for Vault Enterprise*.

Use the [`vault_secrets_import_plan`](../d/secrets_import_plan.html) data source to preview
an import without writing anything.

~> **Experimental** This resource targets the proof-of-concept
`POST sys/import/sources/:type/:name/apply` API, which runs synchronously. Large imports can exceed the
Vault client timeout.

~> **Important** Imported secret values are never returned or stored in state; only
destination paths, counts and errors are.

## Example Usage

```hcl
# Import. Bump "import" to apply the source again.
resource "vault_secrets_import_apply" "aws" {
  type     = "aws-sm"
  name     = vault_secrets_import_aws_source.prod.name
  triggers = { import = "1" }
}

output "imported_count" {
  value = vault_secrets_import_apply.aws.imported_count
}
```

## Argument Reference

The following arguments are supported:

* `type` - (Required) Type of the import source: `aws-sm`, `azure-kv` or `gcp-sm`.
  Changing this forces a new resource.

* `name` - (Required) Name of the import source to apply. Changing this forces a new resource.

* `triggers` - (Optional) Arbitrary map of values that cause the source to be applied again when changed.

* `fail_on_error` - (Optional) Return an error when any secret fails to import. The resource
  is then tainted, so the next apply runs the import again. When `false`, failures are
  reported as warnings. Defaults to `true`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `applied_at` - Time the import ran.

* `auth_mode` - How Vault authenticated to the cloud provider.

* `destination_mount` - KV v2 mount the secrets were imported into.

* `scanned_count` - Number of secrets found in the source.

* `imported` - Destination paths of the secrets imported.

* `imported_count` - Number of secrets imported.

* `ignored` - Source secrets not selected by the source's filter.

* `failed` - Map of destination paths that failed to import to the error.

* `failed_count` - Number of secrets that failed to import.

## Import

This resource does not support import.
