---
layout: "vault"
page_title: "Vault: ephemeral vault_database_secret resource"
sidebar_current: "docs-vault-ephemeral-database-secret"
description: |-
  Read an ephemeral dynamic secret from the Vault Database Secrets engine

---

# vault\_database\_secret

Reads an ephemeral dynamic secret from the Vault Database Secrets engine that is not stored in the remote TF state.
This resource supports all credential types available in the database secrets engine: `password`, `rsa_private_key`, and `client_certificate`.
For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/docs/secrets/databases)
for the DB Secrets engine.

## Example Usage

### Password Credentials (Default)

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

### RSA Private Key Credentials

```hcl
resource "vault_database_secrets_mount" "snowflake" {
  path = "snowflake"

  snowflake {
    name                     = "snowflake-db"
    connection_url           = "username.account.snowflakecomputing.com"
    username                 = "VAULT_USER"
    allowed_roles            = ["*"]
    username_template        = "vault-{{.DisplayName}}-{{random 20}}"
    private_key_wo           = file("/path/to/private_key.pem")
    private_key_wo_version   = "1"
  }
}

resource "vault_database_secret_backend_role" "rsa_role" {
  backend             = vault_database_secrets_mount.snowflake.path
  name                = "snowflake-rsa-role"
  db_name             = vault_database_secrets_mount.snowflake.snowflake[0].name
  credential_type     = "rsa_private_key"
  creation_statements = [
    "CREATE USER IF NOT EXISTS \"{{name}}\";",
    "ALTER USER \"{{name}}\" SET RSA_PUBLIC_KEY='{{public_key}}';"
  ]
  revocation_statements = [
    "DROP USER IF EXISTS \"{{name}}\";"
  ]
  default_ttl = 300
  max_ttl     = 600
}

ephemeral "vault_database_secret" "db_rsa_credentials" {
  mount    = vault_database_secrets_mount.snowflake.path
  name     = vault_database_secret_backend_role.rsa_role.name
  mount_id = vault_database_secrets_mount.snowflake.id
}
```

### Client Certificate Credentials

```hcl
resource "vault_database_secrets_mount" "mongodbatlas" {
  path = "mongodbatlas"

  mongodbatlas {
    name          = "atlas-db"
    private_key   = "your-private-key"
    public_key    = "your-public-key"
    project_id    = "your-project-id"
    allowed_roles = ["*"]
  }
}

resource "vault_database_secret_backend_role" "cert_role" {
  backend             = vault_database_secrets_mount.mongodbatlas.path
  name                = "atlas-cert-role"
  db_name             = vault_database_secrets_mount.mongodbatlas.mongodbatlas[0].name
  credential_type     = "client_certificate"
  default_ttl         = 1800
  max_ttl             = 3600
  creation_statements = [jsonencode({
    database_name : "$external",
    x509Type : "CUSTOMER",
    roles : [{ databaseName : "sample_training", roleName : "readWrite" }]
  })]
  credential_config = {
    ca_cert              = file("/path/to/ca_cert.pem")
    ca_private_key       = file("/path/to/ca_key.pem")
    key_type             = "rsa"
    key_bits             = "2048"
    signature_bits       = "256"
    common_name_template = "{{.RoleName}}_{{unix_time}}"
  }
}

ephemeral "vault_database_secret" "db_cert_credentials" {
  mount    = vault_database_secrets_mount.mongodbatlas.path
  name     = vault_database_secret_backend_role.cert_role.name
  mount_id = vault_database_secrets_mount.mongodbatlas.id
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

* `rsa_private_key` - RSA private key for the newly created DB user. Only populated when the role's credential_type is `rsa_private_key`.

* `client_certificate` - Client certificate for the newly created DB user. Only populated when the role's credential_type is `client_certificate`.

* `private_key` - Private key for the newly created DB user. Only populated when the role's credential_type is `client_certificate`.

* `private_key_type` - Type of private key (e.g., 'rsa', 'ec'). Only populated when the role's credential_type is `client_certificate`.
