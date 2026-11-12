---
layout: "vault"
page_title: "Vault: vault_secrets_import_gcp_source resource"
sidebar_current: "docs-vault-resource-secrets-import-gcp-source"
description: |-
  Manages a secrets import source that imports GCP Secret Manager secrets into a KV v2 mount.
---

# vault\_secrets\_import\_gcp\_source

Manages a GCP Secret Manager secrets import source. A source describes which GCP Secret Manager to read,
how Vault authenticates to it, and the KV v2 mount the secrets are imported into. Use the
[`vault_secrets_import_plan`](../d/secrets_import_plan.html) data source to preview an
import and [`vault_secrets_import_apply`](secrets_import_apply.html) to run it, both with
`type = "gcp-sm"`.
*Available only for Vault Enterprise*. Sources are only supported in the root namespace.

Vault picks the authentication mode from the arguments that are set:

* `identity_token_audience` and `service_account_email` - workload identity federation (WIF).
* `credentials` - static service account key.
* Neither - the Vault server's host credentials (Application Default Credentials).

~> **Experimental** This resource targets the proof-of-concept
`sys/import/sources/gcp-sm/:name` API.

~> **Important** Static credentials are a fallback for environments without host
credentials or WIF. Vault accepts them with a warning. They are stored in Terraform state,
so protect the state accordingly.

## Example Usage

```hcl
resource "vault_secrets_import_gcp_source" "prod" {
  name                    = "gcp-prod"
  project_id              = "my-project"
  service_account_email   = "vault-import@my-project.iam.gserviceaccount.com"
  identity_token_audience = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/vault/providers/vault"
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
  identity federation. When set, Vault uses workload identity federation (WIF). Requires `service_account_email`.

* `identity_token_key` - (Optional) Identity token key used to sign the workload identity token.
  Requires `identity_token_audience`.

* `identity_token_ttl` - (Optional) TTL of the workload identity token, in seconds.
  Requires `identity_token_audience`.

GCP:

* `project_id` - (Required) Project to import secrets from.

* `service_account_email` - (Optional) Service account to impersonate. Required with
  `identity_token_audience`.

* `credentials` - (Optional, Sensitive) Static service account key JSON. Conflicts with
  `identity_token_audience`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `auth_mode` - How Vault authenticates to the cloud provider: `host_credentials`, `static_credentials` or `workload_identity_federation`.

* `created_at` - Time the source was created.

* `updated_at` - Time the source was last updated.

## Import

GCP sources can be imported using the `name`, e.g.

```
$ terraform import vault_secrets_import_gcp_source.example gcp-prod
```

Static credentials are masked by Vault and are not read back, so they are empty after
import. Set them in the configuration again.
