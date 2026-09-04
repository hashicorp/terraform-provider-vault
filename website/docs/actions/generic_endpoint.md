---
layout: "vault"
page_title: "Vault: vault_generic_endpoint action"
sidebar_current: "docs-vault-action-generic-endpoint"
description: |-
  Writes to an arbitrary Vault endpoint.
---

# vault\_generic\_endpoint

~> **Experimental:** Terraform actions are an experimental feature available in
Terraform 1.14.0 and later. Their behavior may change in future releases.

Writes to an arbitrary Vault endpoint as a Terraform action. This is intended
for operational endpoints that perform work but hold no Terraform-managed
state — most commonly `rotate-root`, but any writable path is accepted.

Because the endpoint is given as a full `path`, the same action covers every
secret engine without engine-specific arguments. Consult the
[Vault API documentation](https://developer.hashicorp.com/vault/api-docs) for
the path and request body a given endpoint expects.

~> **Important:** Rotating root credentials is irreversible. The new credential
is held only by Vault and is **not** recoverable afterwards. Always configure
Vault with a dedicated service account rather than the real root user. See the
[rotate root documentation](https://developer.hashicorp.com/vault/api-docs/secret/databases#rotate-root-credentials)
for details.

## Example Usage

### Rotating root credentials

Actions are invoked through a `lifecycle.action_trigger` block on a resource.
There is no standalone command to run an action.

```hcl
resource "vault_mount" "db" {
  path = "database"
  type = "database"
}

resource "vault_database_secret_backend_connection" "postgres" {
  backend       = vault_mount.db.path
  name          = "postgres"
  allowed_roles = ["*"]

  postgresql {
    connection_url = "postgres://root:password@localhost:5432/postgres"
  }

  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.vault_generic_endpoint.rotate_postgres]
    }
  }
}

action "vault_generic_endpoint" "rotate_postgres" {
  config {
    path = "${vault_mount.db.path}/rotate-root/${vault_database_secret_backend_connection.postgres.name}"
  }
}
```

### Rotate root paths by engine

Vault is not consistent about where `rotate-root` lives. Give `path` the full
endpoint for the engine in question:

| Engine | Path |
|---|---|
| Database | `{mount}/rotate-root/{connection_name}` |
| AWS | `{mount}/config/rotate-root` |
| GCP | `{mount}/config/rotate-root` |
| Azure | `{mount}/rotate-root` |
| Active Directory | `{mount}/rotate-root` |
| LDAP | `{mount}/rotate-root` |

```hcl
action "vault_generic_endpoint" "rotate_aws" {
  config {
    path = "aws/config/rotate-root"
  }
}

action "vault_generic_endpoint" "rotate_ldap" {
  config {
    path = "ldap/rotate-root"
  }
}
```

### Writing a request body

Endpoints that take parameters accept them as JSON via `data_json`:

```hcl
action "vault_generic_endpoint" "write_policy" {
  config {
    path = "sys/policies/acl/example"
    data_json = jsonencode({
      policy = "path \"secret/*\" { capabilities = [\"read\"] }"
    })
  }
}
```

## Argument Reference

The following arguments are supported inside the `config` block:

* `path` - (Required) Full path of the Vault endpoint to write to, without a
  leading or trailing slash. For example, `aws/config/rotate-root`.

* `data_json` - (Optional) JSON-encoded object sent as the request body. Omit
  for endpoints that take no parameters, such as `rotate-root`.

* `timeout_seconds` - (Optional) Maximum time in seconds to wait for the write
  to complete. Must be between 60 and 7200. Defaults to `1800`.

* `namespace` - (Optional) The namespace to write to. The value should not
  contain leading or trailing forward slashes. The `namespace` is always
  relative to the provider's configured
  [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*. On Vault Community Edition this field
  is ignored rather than rejected, and the write is sent to the root namespace.

## Required Vault capabilities

The token used by the provider needs:

* `update` on the `path` being written, and
* `create`/`update` on `auth/token/create`, which the provider uses to mint a
  short-lived child token for the request.

A token missing the second is reported as a client configuration failure rather
than a permissions error.
