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
This action calls `POST /{backend}/rotate-root` against the Vault API. When
`name` is set, the path is `POST /{backend}/rotate-root/{name}`.

## Example Usage

### Database Connection

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

### AWS / GCP

AWS and GCP rotate root credentials at `{mount}/config/rotate-root`. Set
`backend` to `{mount}/config` and omit `name`.

```hcl
resource "vault_aws_secret_backend" "aws" {
  access_key = "AKIA....."
  secret_key = "AWS secret key"

  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.vault_secret_backend_rotate_root.aws]
    }
  }
}

action "vault_secret_backend_rotate_root" "aws" {
  config {
    backend = "${vault_aws_secret_backend.aws.path}/config"
  }
}
```

### Azure / AD / LDAP

Azure, Active Directory, and LDAP rotate root credentials at
`{mount}/rotate-root`. Set `backend` to the mount path and omit `name`.

```hcl
resource "vault_azure_secret_backend" "azure" {
  subscription_id = "11111111-2222-3333-4444-111111111111"
  tenant_id       = "11111111-2222-3333-4444-222222222222"
  client_id       = "11111111-2222-3333-4444-333333333333"
  client_secret   = "12345678901234567890"

  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.vault_secret_backend_rotate_root.azure]
    }
  }
}

action "vault_secret_backend_rotate_root" "azure" {
  config {
    backend = vault_azure_secret_backend.azure.path
  }
}
```

## Argument Reference

The following arguments are supported inside the `config` block:

* `backend` - (Required) The path of the secret backend mount. For AWS and GCP,
  include the `/config` suffix (for example, `aws/config` or `gcp/config`).

* `name` - (Optional) The name of the connection to rotate root credentials for.
  Required for database secret backends. Omit for AWS, GCP, Azure, AD, and LDAP.

* `timeout_seconds` - (Optional) Maximum time in seconds to wait for the
  rotation to complete. Must be between 60 and 7200. Defaults to `1800`.

* `namespace` - (Optional) The namespace to provision the action in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured
  [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.
