---
layout: "vault"
page_title: "Vault: vault_mount resource"
sidebar_current: "docs-vault-resource-mount"
description: |-
  Managing the mounting of secret backends in Vault
---

# vault\_mount


## Example Usage

```hcl
resource "vault_mount" "example" {
  path        = "dummy"
  type        = "generic"
  description = "This is an example mount"
}
```

```hcl
resource "vault_mount" "kvv2-example" {
  path        = "version2-example"
  type        = "kv-v2"
  description = "This is an example KV Version 2 secret engine mount"
}
```

```hcl
resource "vault_mount" "transit-example" {
  path        = "transit-example"
  type        = "transit"
  description = "This is an example transit secret engine mount"

  options = {
    convergent_encryption = false
  }
}
```

```hcl
resource "vault_mount" "pki-example" {
  path        = "pki-example"
  type        = "pki"
  description = "This is an example PKI mount"

  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) Where the secret backend will be mounted

* `type` - (Required) Type of the backend, such as "aws"

* `description` - (Optional) Human-friendly description of the mount

* `default_lease_ttl_seconds` - (Optional) Default lease duration for tokens and secrets in seconds

* `max_lease_ttl_seconds` - (Optional) Maximum possible lease duration for tokens and secrets in seconds

* `local` - (Optional) Boolean flag that can be explicitly set to true to enforce local mount in HA environment

* `options` - (Optional) Specifies mount type specific options that are passed to the backend

* `seal_wrap` - (Optional) Boolean flag that can be explicitly set to true to enable seal wrapping for the mount, causing values stored by the mount to be wrapped by the seal's encryption capability

* `external_entropy_access` - (Optional) Boolean flag that can be explicitly set to true to enable the secrets engine to access Vault's external entropy source

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `accessor` - The accessor for this mount.

## Import

Mounts can be imported using the `path`, e.g.

```
$ terraform import vault_mount.example dummy
```
