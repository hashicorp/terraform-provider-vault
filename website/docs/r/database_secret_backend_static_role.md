---
layout: "vault"
page_title: "Vault: vault_database_secret_backend_static_role resource"
sidebar_current: "docs-vault-resource-database-secret-backend-static-role"
description: |-
  Configures a database secret backend static role for Vault.
---

# vault\_database\_secret\_backend\_static\_role

Creates a Database Secret Backend static role in Vault. Database secret backend
static roles can be used to manage 1-to-1 mapping of a Vault Role to a user in a
database for the database.

## Example Usage

```hcl
resource "vault_mount" "db" {
  path = "postgres"
  type = "database"
}

resource "vault_database_secret_backend_connection" "postgres" {
  backend       = vault_mount.db.path
  name          = "postgres"
  allowed_roles = ["*"]

  postgresql {
    connection_url = "postgres://username:password@host:port/database"
  }
}

resource "vault_database_secret_backend_static_role" "static_role" {
  backend             = vault_mount.db.path
  name                = "my-static-role"
  db_name             = vault_database_secret_backend_connection.postgres.name
  username            = "example"
  rotation_period     = "3600"
  rotation_statements = ["ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) A unique name to give the static role.

* `backend` - (Required) The unique name of the Vault mount to configure.

* `db_name` - (Required) The unique name of the database connection to use for the static role.

* `username` - (Required) The database username that this static role corresponds to.

* `rotation_period` - (Required) The amount of time Vault should wait before rotating the password, in seconds.

* `rotation_statements` - (Optional) Database statements to execute to rotate the password for the configured database user.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Database secret backend static roles can be imported using the `backend`, `/static-roles/`, and the `name` e.g.

```
$ terraform import vault_database_secret_backend_static_role.example postgres/static-roles/my-role
```
