---
layout: "vault"
page_title: "Vault: vault_kv_secret_v2_metadata data source"
sidebar_current: "docs-vault-datasource-kv-secret-v2-metadata"
description: |-
 Reads a KV-V2 secret's metadata from a given path in Vault
---

# vault\_kv\_secret\_v2\_metadata

Reads a KV-V2 secret's metadata from a given path in Vault without exposing the secret content.

This data source is primarily intended to be used with the `vault_kv_secret_v2` ephemeral data source.
It provides non-ephemeral access to the secret's version number and other metadata without loading the sensitive secret content into the state file.
The non-ephemeral version can then be used to [control updates of write-only arguments](https://developer.hashicorp.com/terraform/language/resources/ephemeral/write-only#update-write-only-arguments-with-versions).


## Example Usage

```hcl
data "vault_kv_secret_v2_metadata" "example" {
  mount = "mount"
  name  = "secret"
}

# Load explicit version to avoid drift between the stateful version and the ephemeral secret data.
ephemeral "vault_kv_secret_v2" "example" {
  mount   = data.vault_kv_secret_v2_metadata.example.mount
  name    = data.vault_kv_secret_v2_metadata.example.name
  version = data.vault_kv_secret_v2_metadata.example.version
}

# Use the ephemeral secret data and stateful version to control updates of write-only arguments.
resource "vault_database_secret_backend_connection" "postgres" {
  postgresql {
    username    = ephemeral.vault_kv_secret_v2.example.data.username
    password_wo = ephemeral.vault_kv_secret_v2.example.data.password

    # Use non-ephemeral version from metadata data source to trigger updates when needed
    password_wo_version = data.vault_kv_secret_v2_metadata.example.version
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where KV-V2 engine is mounted.

* `name` - (Required) Full name of the secret. For a nested secret
  the name is the nested path excluding the mount and data
  prefix. For example, for a secret at `kvv2/data/foo/bar/baz`
  the name is `foo/bar/baz`.

* `version` - (Optional) Specific version of the secret metadata to retrieve.
  If not specified, the latest version's metadata is returned.

## Required Vault Capabilities

Use of this resource requires the `read` capability on the given path.

## Attributes Reference

The following attributes are exported:

* `path` - (string) Full path where the KVV2 secret is written.

* `created_time` - (string) Time at which secret was created.

* `custom_metadata` - (map of strings) Custom metadata for the secret.

* `deletion_time` - (string) Deletion time for the secret.

* `destroyed` - (bool) Indicates whether the secret has been destroyed.

* `version` - (int) Version of the secret.
