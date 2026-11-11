---
layout: "vault"
page_title: "Vault: vault_secrets_import_aws_source resource"
sidebar_current: "docs-vault-resource-secrets-import-aws-source"
description: |-
  Manages a secrets import source that imports AWS Secrets Manager secrets into a KV v2 mount.
---

# vault\_secrets\_import\_aws\_source

Manages an AWS Secrets Manager secrets import source. A source describes which AWS Secrets Manager to read,
how Vault authenticates to it, and the KV v2 mount the secrets are imported into. Use the
[`vault_secrets_import_plan`](../d/secrets_import_plan.html) data source to preview an
import and [`vault_secrets_import_apply`](secrets_import_apply.html) to run it, both with
`type = "aws-sm"`.
*Available only for Vault Enterprise*. Sources are only supported in the root namespace.

Vault picks the authentication mode from the arguments that are set:

* `identity_token_audience` and `role_arn` - workload identity federation (WIF).
* `access_key_id` and `secret_access_key` - static credentials, optionally assuming `role_arn`.
* `role_arn` only - the Vault server's host credentials assume `role_arn`.
* None of these - the Vault server's host credentials.

~> **Experimental** This resource targets the proof-of-concept
`sys/import/sources/aws-sm/:name` API.

~> **Important** Static credentials are a fallback for environments without host
credentials or WIF. Vault accepts them with a warning. They are stored in Terraform state,
so protect the state accordingly.

## Example Usage

```hcl
resource "vault_mount" "kvv2" {
  path    = "imported"
  type    = "kv"
  options = { version = "2" }
}

resource "vault_secrets_import_aws_source" "prod" {
  name                    = "aws-prod"
  region                  = "us-east-1"
  role_arn                = "arn:aws:iam::123456789012:role/vault-import"
  identity_token_audience = "vault-import"
  destination_mount       = vault_mount.kvv2.path
  filter                  = "\"prod\" in Secret.Name"
}
```

One source per AWS account and region:

```hcl
resource "vault_secrets_import_aws_source" "accounts" {
  for_each = var.accounts # map of name => { account_id, region }

  name                    = each.key
  region                  = each.value.region
  role_arn                = "arn:aws:iam::${each.value.account_id}:role/vault-import"
  identity_token_audience = "vault-import"
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
  identity federation. When set, Vault uses workload identity federation (WIF). Requires `role_arn`.

* `identity_token_key` - (Optional) Identity token key used to sign the workload identity token.
  Requires `identity_token_audience`.

* `identity_token_ttl` - (Optional) TTL of the workload identity token, in seconds.
  Requires `identity_token_audience`.

AWS:

* `region` - (Optional) Region to import secrets from.

* `role_arn` - (Optional) IAM role ARN to assume, e.g. `arn:aws:iam::123456789012:role/name`.
  Required with `identity_token_audience`.

* `external_id` - (Optional) External ID matching the trust policy of `role_arn`.
  Requires `role_arn`. Conflicts with `identity_token_audience`.

* `access_key_id` - (Optional, Sensitive) Static access key ID. Requires `secret_access_key`.
  Conflicts with `identity_token_audience`.

* `secret_access_key` - (Optional, Sensitive) Static secret access key. Requires
  `access_key_id`. Conflicts with `identity_token_audience`.

* `session_token` - (Optional, Sensitive) Session token for temporary static credentials.
  Requires `access_key_id` and `secret_access_key`. Conflicts with `identity_token_audience`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `auth_mode` - How Vault authenticates to the cloud provider: `host_credentials`, `host_credentials_assume_role`, `static_credentials` or
  `workload_identity_federation`.

* `created_at` - Time the source was created.

* `updated_at` - Time the source was last updated.

## Import

AWS sources can be imported using the `name`, e.g.

```
$ terraform import vault_secrets_import_aws_source.example aws-prod
```

Static credentials are masked by Vault and are not read back, so they are empty after
import. Set them in the configuration again.
