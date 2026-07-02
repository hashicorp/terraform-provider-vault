---
layout: "vault"
page_title: "Vault: vault_secret_backend_rotate_root action"
sidebar_current: "docs-vault-action-secret-backend-rotate-root"
description: |-
  Rotates the root credentials for a Vault secret backend connection.
---

# vault\_secret\_backend\_rotate\_root

~> **Experimental:** Terraform actions are an experimental feature available in
Terraform 1.14.0 and later. Their behavior may change in future releases.

~> **Important:** The root user's password will **not** be accessible after
rotation. Ensure you have a Vault-specific database user rather than using the
actual root user. See the
[Vault API documentation](https://developer.hashicorp.com/vault/api-docs/secret/databases#rotate-root-credentials)
for more details.

Rotates the root credentials stored for a secret backend connection in Vault.
This action calls `POST /{backend}/rotate-root/{name}` against the Vault API.

## Example Usage

### Rotate After Connection Creation

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
      actions = [action.vault_secret_backend_rotate_root.postgres]
    }
  }
}

action "vault_secret_backend_rotate_root" "postgres" {
  config {
    backend = vault_mount.db.path
    name    = vault_database_secret_backend_connection.postgres.name
  }
}
```

### Rotate After Connection Updates

```hcl
resource "vault_database_secret_backend_connection" "postgres" {
  backend       = vault_mount.db.path
  name          = "postgres"
  allowed_roles = ["*"]

  postgresql {
    connection_url = "postgres://root:password@localhost:5432/postgres"
  }

  lifecycle {
    action_trigger {
      events  = [after_create, after_update]
      actions = [action.vault_secret_backend_rotate_root.postgres]
    }
  }
}

action "vault_secret_backend_rotate_root" "postgres" {
  config {
    backend         = vault_mount.db.path
    name            = vault_database_secret_backend_connection.postgres.name
    timeout_seconds = 120
  }
}
```

## Argument Reference

The following arguments are supported inside the `config` block:

* `backend` - (Required) The path of the secret backend mount.

* `name` - (Required) The name of the connection to rotate root credentials for.

* `timeout_seconds` - (Optional) Maximum time in seconds to wait for the
  rotation to complete. Must be between 60 and 7200. Defaults to `1800`.

* `namespace` - (Optional) The namespace to provision the action in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured
  [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.
