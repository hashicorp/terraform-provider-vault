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

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required) A unique name to give the static role.

* `backend` - (Required) The unique name of the Vault mount to configure.

* `db_name` - (Required) The unique name of the database connection to use for the static role.

* `username` - (Required) The database username that this static role corresponds to.

* `rotation_period` - (Required) The amount of time Vault should wait before rotating the password, in seconds.

* `rotation_statements` - (Optional) Database statements to execute to rotate the password for the configured database user.

* `credential_type` (Optional) – Specifies the type of credential that
  will be generated for the role. Options include: `password`, `rsa_private_key`, `client_certificate`.
  See the plugin's API page for credential types supported by individual databases.

* `credential_config` (Optional) – Specifies the configuration
  for the given `credential_type`.

  The following options are available for each `credential_type` value:

    * `password`
        * `password_policy` (Optional) - The [policy](/vault/docs/concepts/password-policies)
          used for password generation. If not provided, defaults to the password policy of the
          database [configuration](/vault/api-docs/secret/databases#password_policy).

    * `rsa_private_key`
        * `key_bits` (Optional) - The bit size of the RSA key to generate. Options include:
          `2048`, `3072`, `4096`.
        * `format` (Optional) - The output format of the generated private key
          credential. The private key will be returned from the API in PEM encoding. Options
          include: `pkcs8`.

    * `client_certificate`
        * `common_name_template` (Optional) - A [username template](/vault/docs/concepts/username-templating)
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

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Database secret backend static roles can be imported using the `backend`, `/static-roles/`, and the `name` e.g.

```
$ terraform import vault_database_secret_backend_static_role.example postgres/static-roles/my-role
```
