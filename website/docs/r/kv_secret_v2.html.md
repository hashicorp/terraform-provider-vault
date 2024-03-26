---
layout: "vault"
page_title: "Vault: vault_kv_secret_v2 resource"
sidebar_current: "docs-vault-resource-kv-secret-v2"
description: |-
  Writes a KV-V2 secret to a given path in Vault
---

# vault\_kv\_secret\_v2

Writes a KV-V2 secret to a given path in Vault.

For more information on Vault's KV-V2 secret backend
[see here](https://www.vaultproject.io/docs/secrets/kv/kv-v2).

## Example Usage

```hcl
resource "vault_mount" "kvv2" {
  path        = "kvv2"
  type        = "kv"
  options     = { version = "2" }
  description = "KV Version 2 secret engine mount"
}

resource "vault_kv_secret_v2" "example" {
  mount                      = vault_mount.kvv2.path
  name                       = "secret"
  cas                        = 1
  delete_all_versions        = true
  data_json                  = jsonencode(
  {
    zip       = "zap",
    foo       = "bar"
  }
  )
  custom_metadata {
    max_versions = 5
    data = {
      foo = "vault@example.com",
      bar = "12345"
    }
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where KV-V2 engine is mounted.

* `name` - (Required) Full name of the secret. For a nested secret
  the name is the nested path excluding the mount and data
  prefix. For example, for a secret at `kvv2/data/foo/bar/baz`
  the name is `foo/bar/baz`.

* `cas` - (Optional) This flag is required if `cas_required` is set to true
  on either the secret or the engine's config. In order for a
  write operation to be successful, cas must be set to the current version
  of the secret.

* `options` - (Optional) An object that holds option settings.

* `disable_read` - (Optional) If set to true, disables reading secret from Vault;
  note: drift won't be detected.

* `delete_all_versions` - (Optional) If set to true, permanently deletes all
  versions for the specified key.

* `data_json` - (Required) JSON-encoded string that will be
  written as the secret data at the given path.

* `custom_metadata` - (Optional) A nested block that allows configuring metadata for the
  KV secret. Refer to the
  [Configuration Options](#custom-metadata-configuration-options) for more info.

## Required Vault Capabilities

Use of this resource requires the `create` or `update` capability
(depending on whether the resource already exists) on the given path,
the `delete` capability if the resource is removed from configuration,
and the `read` capability for drift detection (by default).

### Custom Metadata Configuration Options

* `max_versions` - (Optional) The number of versions to keep per key.

* `cas_required` - (Optional) If true, all keys will require the cas
  parameter to be set on all write requests.

* `delete_version_after` - (Optional) If set, specifies the length of time before
  a version is deleted. Accepts duration in integer seconds.

* `data` - (Optional) A string to string map describing the secret.

## Attributes Reference

The following attributes are exported in addition to the above:

* `path` - Full path where the KV-V2 secret will be written.

* `data` - A mapping whose keys are the top-level data keys returned from
Vault and whose values are the corresponding values. This map can only
represent string data, so any non-string values returned from Vault are
serialized as JSON.

* `metadata` - Metadata associated with this secret read from Vault.

## Import

KV-V2 secrets can be imported using the `path`, e.g.

```
$ terraform import vault_kv_secret_v2.example kvv2/data/secret
```
