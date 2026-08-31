---
layout: "vault"
page_title: "Vault: vault_transform_transformation_tokenization_store resource"
sidebar_current: "docs-vault-resource-transform-transformation-tokenization-store"
description: |-
  "/transform/stores/{name}"
---

# vault\_transform\_transformation\_tokenization\_store

This resource supports the "/transform/stores/{name}" Vault endpoint.

If a tokenization store with the given name doesn't exist, it will be created. If a tokenization store with the given name exists, it will be updated with the new attributes.

## Example Usage

```hcl
resource "vault_mount" "example" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_transformation_tokenization_store" "example" {
  path                      = vault_mount.example.path
  name                      = "my-store"
  type                      = "sql"
  driver                    = "postgres"
  connection_string         = "postgresql://{{username}}:{{password}}@127.0.0.1:5432/vault?sslmode=disable"
  username                  = "vaultuser"
  password                  = "vaultpass"
  supported_transformations = ["tokenization"]
}

resource "vault_transform_transformation_tokenization" "example" {
  path             = vault_mount.example.path
  name             = "tkn-example"
  stores           = [vault_transform_transformation_tokenization_store.example.name]
  deletion_allowed = true
  allowed_roles    = ["payments"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Required) Path to where the back-end is mounted within Vault.
* `name` - (Required) Name of the store to create or update.
* `type` - (Required) Specifies the type of store, currently only `sql` is supported.
* `driver` - (Required) Specifies the database driver to use, and thus which SQL database type. Currently the supported options are `postgres`, `mysql`, and `mssql`.
* `connection_string` - (Required) A database connection string with template slots for username and password that Vault will use for locating and connecting to a database. Each database driver type has a different syntax for its connection strings.
**Note:** When using MySQL, make sure to append ?parseTime=true to enable timestamp parsing.
* `username` - (Required) The username value to use when connecting to the database.
* `password` - (Required) The password value to use when connecting to the database.
* `supported_transformations` - (Optional) The list of transformations that this store can support. Currently, only `tokenization` is supported. Default is `[tokenization]`
* `schema` - (Optional) The schema within the database to expect tokenization state tables. Default is `public`.
* `max_open_connections` - (Optional) The maximum number of connections to the database at any given time. Default is `4`.
* `max_idle_connections` - (Optional) The maximum number of idle connections to the database at any given time. Default is `4`.
* `max_connection_lifetime` - (Optional) The maximum amount of time a connection can be open before closing it. 0 means no limit. Default is `0`.

