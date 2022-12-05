---
layout: "vault"
page_title: "Vault: vault_kv_secret_metadata_v2 resource"
sidebar_current: "docs-vault-resource-kv-secret-metadata-v2"
description: |-
  Configures KV-V2 metadata at a specified secret location. 
---

# vault\_kv\_secret\_metadata\_v2

Configures KV-V2 metadata at a specified secret location.

For more information on Vault's KV-V2 secret metadata
[see here](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#create-update-metadata).

## Example Usage

```hcl
resource "vault_mount" "example" {
  path        = "kvv2"
  type        = "kv"
  options     = { version = "2" }
  description = "KV Version 2 secret engine mount"
}

resource "vault_kv_secret_v2" "example" {
  mount                      = vault_mount.kvv2.path
  name                       = "secret-1"
  delete_all_versions        = true
  data_json                  = jsonencode(
  {
    zip       = "zap",
    foo       = "bar",
  }
  )
}

resource "vault_kv_secret_metadata_v2" "example" {
  mount                = vault_mount.kvv2.path
  name                 = "secret-1"
  max_versions         = 5
  delete_version_after = 3700
  custom_metadata_json = jsonencode(
  {
    fizz = "buzz",
  }
  )
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where KV-V2 engine is mounted.

* `name` - (Required) Unique identifier for the secret metadata.

* `max_versions` - (Optional) The number of versions to keep per key.

* `cas_required` - (Optional) If true, all keys will require the cas
  parameter to be set on all write requests.

* `delete_version_after` - (Optional) If set, specifies the length of time before
  a version is deleted. Accepts duration in integer seconds.

*`custom_metadata_json` - (Optional) JSON-encoded secret metadata to write.

## Required Vault Capabilities

Use of this resource requires the `create` or `update` capability
(depending on whether the resource already exists) on the given path,
the `delete` capability if the resource is removed from configuration,
and the `read` capability for drift detection (by default).

## Attributes Reference

The following attributes are exported in addition to the above:

* `path` - Full path where the KV-V2 secret will be written.

* `custom_metadata` - A mapping whose keys are the top-level metadata 
  keys returned from Vault and whose values are the corresponding values.
  This map can only represent string data, so any non-string values
  returned from Vault are serialized as JSON.


## Import

KV-V2 secret metadata can be imported using the `path`, e.g.

```
$ terraform import vault_kv_secret_v2.secret kvv2/metadata/secret-1
```
