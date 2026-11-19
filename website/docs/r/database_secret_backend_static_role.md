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

# configure a static role with a password (Vault 1.19+)
resource "vault_database_secret_backend_static_role" "password_role" {
  backend             = vault_mount.db.path
  name                = "my-password-role"
  db_name             = vault_database_secret_backend_connection.postgres.name
  username            = "example"
  password_wo         = "my-password"
  password_wo_version = 1
  rotation_period     = "3600"
  rotation_statements = ["ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]
}

# configure a static role that generates passwords using a custom password policy
resource "vault_database_secret_backend_static_role" "policy_role" {
  backend             = vault_mount.db.path
  name                = "my-policy-role"
  db_name             = vault_database_secret_backend_connection.postgres.name
  username            = "example"
  rotation_period     = "3600"
  rotation_statements = ["ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]

  credential_type = "password"
  credential_config = {
    password_policy = "my-password-policy"
  }
}
```

A static role can also manage an RSA key pair instead of a password, for example
for Snowflake key-pair authentication:

```hcl
resource "vault_database_secret_backend_static_role" "rsa_role" {
  backend         = vault_mount.db.path
  name            = "my-rsa-role"
  db_name         = vault_database_secret_backend_connection.snowflake.name
  username        = "EXAMPLE_USER"
  rotation_period = "86400"

  credential_type = "rsa_private_key"
  credential_config = {
    key_bits = "4096"
    format   = "pkcs8"
  }
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
  **Deprecated**: Use `password_wo` instead. This field will be removed in a future version.

* `password_wo` - (Optional) The password corresponding to the username in the database.
  This is a write-only field. Requires Vault 1.19+. Deprecates `self_managed_password` which was introduced in Vault 1.18.
  Cannot be used with `self_managed_password`.

* `password_wo_version` - (Optional) The version of the `password_wo` field. 
  Used for tracking changes to the write-only password field. For more info see 
  [updating write-only attributes](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_write_only_attributes.html#updating-write-only-attributes).

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

* `credential_type` - (Optional) Specifies the type of credential that
  will be generated for the role. Options include: `password`, `rsa_private_key`, `client_certificate`.
  Defaults to `password` in Vault. See the plugin's API page for credential types supported by individual databases.

* `credential_config` - (Optional) A map of string key/value pairs that specifies the configuration
  for the given `credential_type`. Note that this is a map argument (`credential_config = { ... }`),
  not a nested block. See the [Vault API documentation](https://developer.hashicorp.com/vault/api-docs/secret/databases#create-static-role)
  for more details.

  The following options are available for each `credential_type` value:

  * `password`
      * `password_policy` (Optional) - The [policy](https://developer.hashicorp.com/vault/docs/concepts/password-policies)
        used for password generation. If not provided, defaults to the password policy of the
        database [configuration](https://developer.hashicorp.com/vault/api-docs/secret/databases#password_policy).

  * `rsa_private_key`
      * `key_bits` (Optional) - The bit size of the RSA key to generate. Options include:
        `2048` (default), `3072`, `4096`.
      * `format` (Optional) - The output format of the generated private key
        credential. The private key will be returned from the API in PEM encoding. Options
        include: `pkcs8` (default).

  * `client_certificate`
      * `common_name_template` (Optional) - A [username template](https://developer.hashicorp.com/vault/docs/concepts/username-templating)
        to be used for the client certificate common name.
      * `ca_cert` (Optional) - The PEM-encoded CA certificate.
      * `ca_private_key` (Optional) - The PEM-encoded private key for the given `ca_cert`.
      * `key_type` (Required) - Specifies the desired key type. Options include:
        `rsa`, `ed25519`, `ec`.
      * `key_bits` (Optional) - Number of bits to use for the generated keys. Options include:
        `2048` (default), `3072`, `4096`; with `key_type=ec`, allowed values are: `224`, `256` (default),
        `384`, `521`; ignored with `key_type=ed25519`.
      * `signature_bits` (Optional) - The number of bits to use in the signature algorithm. Options include:
        `256` (default), `384`, `512`.

  ~> **Note:** All values in `credential_config` are strings, so numeric options such as
  `key_bits` must be quoted, e.g. `key_bits = "4096"`.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Database secret backend static roles can be imported using the `backend`, `/static-roles/`, and the `name` e.g.

```
$ terraform import vault_database_secret_backend_static_role.example postgres/static-roles/my-role
```
