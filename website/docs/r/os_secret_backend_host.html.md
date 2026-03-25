---
layout: "vault"
page_title: "Vault: vault_os_secret_backend_host resource"
sidebar_current: "docs-vault-resource-os-secret-backend-host"
description: |-
  Manages OS Secrets Engine host configurations in Vault.
---

# vault\_os\_secret\_backend\_host

Manages host configurations in the OS Secrets Engine. Hosts represent remote systems where
Vault will manage operating system account credentials via SSH. This resource requires Vault 2.0.0 or later.

See the [Vault documentation](https://www.vaultproject.io/docs/secrets/os) for more information.

## Example Usage

### Basic Host Configuration

```hcl
resource "vault_os_secret_backend" "os" {
  path = "os"
}

resource "vault_os_secret_backend_host" "example" {
  mount   = vault_os_secret_backend.os.path
  name    = "web-server-01"
  type    = "ssh"
  address = "192.168.1.100"
  port    = 22
}
```

### Advanced Host Configuration

```hcl
resource "vault_os_secret_backend" "os" {
  path = "os"
}

resource "vault_os_secret_backend_host" "production" {
  mount             = vault_os_secret_backend.os.path
  name              = "prod-db-01"
  type              = "ssh"
  address           = "10.0.1.50"
  port              = 2222
  rotation_period   = 86400  # 24 hours
  rotation_window   = 3600   # 1 hour
  rotation_schedule = "0 2 * * *"  # Daily at 2 AM

  custom_metadata = {
    environment = "production"
    team        = "database"
    criticality = "high"
  }
}
```

### Host with SSH Host Key

```hcl
resource "vault_os_secret_backend" "os" {
  path = "os"
}

resource "vault_os_secret_backend_host" "secure" {
  mount        = vault_os_secret_backend.os.path
  name         = "secure-host"
  type         = "ssh"
  address      = "192.168.1.200"
  port         = 22
  ssh_host_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `mount` - (Required) The path where the OS secrets engine is mounted.

* `name` - (Required) Unique name for the host within the mount.

* `type` - (Required) The type of connection to use. Currently only `"ssh"` is supported.

* `address` - (Required) The address of the host (IP address or hostname).

* `port` - (Optional) The port to connect to on the host. Defaults to `22` for SSH.

* `ssh_host_key` - (Optional) The SSH host key for the remote host. If not provided and `ssh_host_key_trust_on_first_use` is enabled on the backend, the key will be automatically captured on first connection.

* `rotation_period` - (Optional) The period in seconds between automatic credential rotations. If not set, credentials will not be automatically rotated.

* `rotation_window` - (Optional) The window in seconds during which rotation can occur. Must be less than `rotation_period`. If not set, rotation can occur at any time during the period.

* `rotation_schedule` - (Optional) A cron-style schedule for credential rotation (e.g., `"0 2 * * *"` for daily at 2 AM). If set, this takes precedence over `rotation_period`.

* `custom_metadata` - (Optional) A map of string key-value pairs for storing custom metadata about the host.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The ID of the host in the format `<mount>/host/<name>`.

## Import

OS Secret backend host can be imported using the format `<mount>/host/<name>`, e.g.

```
$ terraform import vault_os_secret_backend_host.example os/host/web-server-01
```

## Notes

* This resource requires Vault 2.0.0 or later.
* The host must be configured before accounts can be created on it.
* When `ssh_host_key` is not provided, the backend's `ssh_host_key_trust_on_first_use` setting determines whether the host key will be automatically trusted on first connection.
* The `rotation_schedule` uses standard cron syntax. If both `rotation_schedule` and `rotation_period` are set, `rotation_schedule` takes precedence.
* The `rotation_window` defines a time window during which rotation can occur, helping to avoid rotating credentials during peak usage times.
* Custom metadata is stored alongside the host configuration and can be used for organizational purposes, but does not affect host behavior.
* Changing `mount` or `name` will cause the resource to be recreated.