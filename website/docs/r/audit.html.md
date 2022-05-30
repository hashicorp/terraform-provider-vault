---
layout: "vault"
page_title: "Vault: vault_audit resource"
sidebar_current: "docs-vault-audit"
description: |-
  Writes audit backends for Vault
---

# vault\_audit

## Example Usage (file audit device)

```hcl
resource "vault_audit" "test" {
  type = "file"

  options = {
    file_path = "C:/temp/audit.txt"
  }
}
```

## Example Usage (socket audit device)

```hcl
resource "vault_audit" "test" {
  type  = "socket"
  path  = "app_socket"
  local = false

  options = {
    address     = "127.0.0.1:8000"
    socket_type = "tcp"
    description = "application x socket"
  }
}
```

## Argument Reference

The following arguments are supported:

* `type` - (Required) Type of the audit device, such as 'file'.

* `path` - (optional) The path to mount the audit device. This defaults to the type.

* `description` - (Optional) Human-friendly description of the audit device.

* `local` - (Optional) Specifies if the audit device is a local only. Local audit devices are not replicated nor (if a secondary) removed by replication.

* `options` - (Required) Configuration options to pass to the audit device itself.

For a reference of the device types and their options, consult the [Vault documentation.](https://www.vaultproject.io/docs/audit/index.html)

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Audit devices can be imported using the `path`, e.g.

```
$ terraform import vault_audit.test syslog
```
