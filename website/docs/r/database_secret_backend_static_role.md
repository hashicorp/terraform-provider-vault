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

# configure a static role with period-based rotations
resource "vault_database_secret_backend_static_role" "period_role" {
  backend             = vault_mount.db.path
  name                = "my-period-role"
  db_name             = vault_database_secret_backend_connection.postgres.name
  username            = "example"
  rotation_period     = "3600"
  rotation_statements = ["ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]
}

# configure a static role with schedule-based rotations
resource "vault_database_secret_backend_static_role" "schedule_role" {
  backend             = vault_mount.db.path
  name                = "my-schedule-role"
  db_name             = vault_database_secret_backend_connection.postgres.name
  username            = "example"
  rotation_schedule   = "0 0 * * SAT"
  rotation_window     = "172800"
  rotation_statements = ["ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required) A unique name to give the static role.

* `backend` - (Required) The unique name of the Vault mount to configure.

* `db_name` - (Required) The unique name of the database connection to use for the static role.

* `username` - (Required) The database username that this static role corresponds to.

* `self_managed_password` - (Optional) The password corresponding to the username in the database.
  Required when using the Rootless Password Rotation workflow for static roles. Only enabled for
  select DB engines (Postgres). Requires Vault 1.18+ Enterprise.

* `skip_import_rotation` - (Optional) If set to true, Vault will skip the
  initial secret rotation on import. Requires Vault 1.18+ Enterprise.

* `rotation_period` - The amount of time Vault should wait before rotating the password, in seconds.
  Mutually exclusive with `rotation_schedule`.

* `rotation_schedule` - A cron-style string that will define the schedule on which rotations should occur.
  Mutually exclusive with `rotation_period`.

**Warning**: The `rotation_period` and `rotation_schedule` fields are
mutually exclusive. One of them must be set but not both.

* `rotation_window` - (Optional) The amount of time, in seconds, in which rotations are allowed to occur starting
  from a given `rotation_schedule`.

* `rotation_statements` - (Optional) Database statements to execute to rotate the password for the configured database user.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Database secret backend static roles can be imported using the `backend`, `/static-roles/`, and the `name` e.g.

```
$ terraform import vault_database_secret_backend_static_role.example postgres/static-roles/my-role
```
