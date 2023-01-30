---
layout: "vault"
page_title: "Vault: vault_kv_secret_backend_v2 resource"
sidebar_current: "docs-vault-resource-kv-secret-backend-v2"
description: |-
  Configures KV-V2 backend level settings that are applied to 
  every key in the key-value store.
---

# vault\_kv\_secret\_backend\_v2

Configures KV-V2 backend level settings that are applied to
every key in the key-value store.

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

resource "vault_kv_secret_backend_v2" "example" {
  mount                = vault_mount.kvv2.path
  max_versions         = 5
  delete_version_after = 12600
  cas_required         = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where KV-V2 engine is mounted.

* `max_versions` - (Optional) The number of versions to keep per key.

* `cas_required` - (Optional) If true, all keys will require the cas
  parameter to be set on all write requests.

* `delete_version_after` - (Optional) If set, specifies the length of time before
  a version is deleted. Accepts duration in integer seconds.

## Required Vault Capabilities

Use of this resource requires the `create` or `update` capability
(depending on whether the resource already exists) on the given path,
the `delete` capability if the resource is removed from configuration,
and the `read` capability for drift detection (by default).

## Attributes Reference

No additional attributes are exported by this resource.

## Import

The KV-V2 secret backend can be imported using its unique ID,
the `${mount}/config`, e.g.

```
$ terraform import vault_kv_secret_backend_v2.example kvv2/config
```
