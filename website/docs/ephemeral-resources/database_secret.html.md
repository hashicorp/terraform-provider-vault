---
layout: "vault"
page_title: "Vault: ephemeral vault_database_secret resource"
sidebar_current: "docs-vault-ephemeral-database-secret"
description: |-
  Read an ephemeral dynamic secret from the Vault Database Secrets engine 

---

# vault\_database\_secret

Reads an ephemeral dynamic secret from the Vault Database Secrets engine that is not stored in the remote TF state.
For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/docs/secrets/databases)
for the DB Secrets engine.

## Example Usage

```hcl
resource "vault_mount" "db" {
  path = "postgres"
  type = "database"
}

resource "vault_database_secret_backend_connection" "postgres" {
  backend       = vault_mount.db.path
  name          = "postrgres-db"
  allowed_roles = ["*"]

  postgresql {
    connection_url = "postgresql://{{username}}:{{password}}@localhost:5432/postgres"
    password_authentication = ""
    username = "postgres"
    password_wo = "pgx-root-password"
    password_wo_version = 1
  }
}

resource "vault_database_secret_backend_role" "role" {
  backend             = vault_mount.db.path
  name                = "pgx-role"
  db_name             = vault_database_secret_backend_connection.postgres.name
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
  ]
}

ephemeral "vault_database_secret" "db_user_credentials" {
  mount = vault_mount.db.path
  name = vault_database_secret_backend_role.role.name
  mount_id = vault_mount.db.id
}
```

## Argument Reference

The following arguments are supported:

* `mount` - (Required) Mount path for the DB engine in Vault without trailing or leading slashes.

* `mount_id` - (Optional) If value is set, will defer provisioning the ephemeral resource until
  `terraform apply`. For more details, please refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

* `name` - (Required) Name of the database role without trailing or leading slashes.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `username` - Username for the newly created DB user.

* `password` - Password for the newly created DB user.
