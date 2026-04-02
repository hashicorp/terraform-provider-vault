---
layout: "vault"
page_title: "Vault: vault_os_secret_backend resource"
sidebar_current: "docs-vault-resource-os-secret-backend"
description: |-
  Manages OS Secrets Engine backend configuration in Vault.
---

# vault\_os\_secret\_backend

Manages OS Secrets Engine backend configuration in a Vault server. The OS Secrets Engine manages credentials
for operating system accounts on remote hosts via SSH. This resource requires Vault 2.0.0 or later.

The OS Secrets Engine mount itself is managed separately, typically with `vault_mount`. This resource only manages
backend configuration for an existing OS mount.

The examples below use the canonical plugin name `vault-plugin-secrets-os`. If your Vault cluster registers the
OS plugin under a different catalog name, use that name in `vault_mount.type` instead.

See the [Vault documentation](https://www.vaultproject.io/docs/secrets/os) for more information.

## Example Usage

### Basic Configuration

```hcl
resource "vault_mount" "os" {
  path = "os"
  type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "os" {
  path = vault_mount.os.path
}
```

### Advanced Configuration

```hcl
resource "vault_mount" "os" {
  path = "os-prod"
  type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "os" {
  path                             = vault_mount.os.path
  max_versions                     = 10
  ssh_host_key_trust_on_first_use  = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) The path where the OS secrets engine is already mounted. Must not begin or end with a `/`.

* `max_versions` - (Optional, Computed) The maximum number of versions to keep. When omitted, Vault applies its server-side default of `10`. If you later remove the field from configuration, Vault retains the current value. Set to `0` to explicitly store zero in Vault.

* `ssh_host_key_trust_on_first_use` - (Optional) If `true`, SSH host keys will be trusted on first use (TOFU). If `false`, host keys must be explicitly configured. Defaults to `false`.

## Import

OS Secret backend can be imported using the `path`, e.g.

```
$ terraform import vault_os_secret_backend.os os
```

## Notes

* This resource requires Vault 2.0.0 or later.
* The OS Secrets Engine must be enabled before this resource can manage its configuration.
* Use `vault_mount` to create, tune, or remove the OS Secrets Engine mount.
* When `ssh_host_key_trust_on_first_use` is enabled, the first connection to a host will automatically trust and store its SSH host key.