---
layout: "vault"
page_title: "Vault: vault_kv_secret resource"
sidebar_current: "docs-vault-resource-kv-secret"
description: |-
  Writes a KV-V1 secret to a given path in Vault
---

# vault\_kv\_secret

Writes a KV-V1 secret to a given path in Vault.

For more information on Vault's KV-V1 secret backend
[see here](https://www.vaultproject.io/docs/secrets/kv/kv-v1).

## Example Usage

```hcl
resource "vault_mount" "kvv1" {
  path        = "kvv1"
  type        = "kv"
  options     = { version = "1" }
  description = "KV Version 1 secret engine mount"
}

resource "vault_kv_secret" "secret" {
  path = "${vault_mount.kvv1.path}/secret"
  data_json = jsonencode(
  {
    zip = "zap",
    foo = "bar"
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

* `path` - (Required) Full path of the KV-V1 secret.

* `data_json` - (Required) JSON-encoded string that will be
  written as the secret data at the given path.

## Required Vault Capabilities

Use of this resource requires the `create` or `update` capability
(depending on whether the resource already exists) on the given path,
the `delete` capability if the resource is removed from configuration,
and the `read` capability for drift detection (by default).

## Attributes Reference

The following attributes are exported in addition to the above:

* `data` - A mapping whose keys are the top-level data keys returned from
Vault and whose values are the corresponding values. This map can only
represent string data, so any non-string values returned from Vault are
serialized as JSON.

## Import

KV-V1 secrets can be imported using the `path`, e.g.

```
$ terraform import vault_kv_secret.secret kvv1/secret
```
