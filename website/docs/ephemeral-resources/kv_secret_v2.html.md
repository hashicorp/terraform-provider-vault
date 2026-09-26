---
layout: "vault"
page_title: "Vault: ephemeral vault_kv_secret_v2 resource"
sidebar_current: "docs-vault-ephemeral-kv-secret-v2"
description: |-
  Read an ephemeral KVV2 secret from Vault 

---

# vault\_kv\_secret\_v2

Reads an ephemeral KVV2 secret from Vault that is not stored in the remote TF state. For more information, please
refer to [the Vault documentation](https://www.vaultproject.io/docs/secrets/kv/kv-v2) for the KVV2 engine.

## Example Usage

```hcl
resource "vault_mount" "kvv2" {
  path    = "my-kvv2"
  type    = "kv"
  options = { version = "2" }
}

resource "vault_kv_secret_v2" "db_root" {
  mount        = vault_mount.kvv2.path
  name         = "pgx-root"
  data_json_wo = jsonencode(
    {
      password = "root-user-password"
    }
  )
  data_json_wo_version = 1
}

#
# Read the database root password and manage a backend connection
#
data "vault_kv_secret_v2_metadata" "db_secret" {
  mount    = vault_mount.kvv2.path
  name     = vault_kv_secret_v2.db_root.name
}

# Load explicit version to avoid drift between the stateful version and the ephemeral secret data.
ephemeral "vault_kv_secret_v2" "db_secret" {
  mount    = vault_mount.kvv2.path
  mount_id = vault_mount.kvv2.id
  name     = data.vault_kv_secret_v2_metadata.db_secret.name
  version  = data.vault_kv_secret_v2_metadata.db_secret.version
}

# Use the ephemeral secret data and stateful version to control updates of write-only arguments.
resource "vault_database_secret_backend_connection" "postgres" {
  backend       = "db-mount"
  name          = "postgres-db"
  allowed_roles = ["*"]

  postgresql {
    connection_url          = "postgresql://{{username}}:{{password}}@localhost:5432/postgres"
    password_authentication = ""
    username                = "postgres"
    password_wo             = ephemeral.vault_kv_secret_v2.db_secret.data.password
    password_wo_version     = data.vault_kv_secret_v2_metadata.db_secret.version
  }
}
```

## Argument Reference

The following arguments are supported:

* `mount` - (Required) Mount path for the KVV2 engine in Vault without trailing or leading slashes.

* `mount_id` - (Optional) If value is set, will defer provisioning the ephemeral resource until
  `terraform apply`. For more details, please refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

* `name` - (Required) Full name of the secret without trailing or leading slashes. For a nested
  secret, the name is the nested path excluding the mount and data prefix. For example, for a
  secret at 'kvv2/data/foo/bar/baz', the name is 'foo/bar/baz'.

* `version` (Optional) Version of the secret to retrieve.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `data` - A mapping whose keys are the top-level data keys returned from
  Vault and whose values are the corresponding values. This map can only
  represent string data, so any non-string values returned from Vault are
  serialized as JSON.

* `data_json` - JSON-encoded string that that is
  read as the secret data at the given path.

* `created_time` - Time at which secret was created.

* `custom_metadata` - Custom metadata for the secret.

* `deletion_time` - Deletion time for the secret.

* `destroyed` - Indicates whether the secret has been destroyed.
