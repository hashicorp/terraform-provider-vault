---
layout: "vault"
page_title: "Vault: vault_tpm_auth_backend_config resource"
sidebar_current: "docs-vault-resource-vault-tpm-auth-backend-config"
description: |-
  Manages TPM auth backend configuration in Vault.
---

# vault\_tpm\_auth\_backend\_config

Manages the configuration for a TPM (Trusted Platform Module) auth backend in Vault.
The TPM auth method allows machines with TPM 2.0 hardware to authenticate to Vault
using their TPM Endorsement Key (EK).

~> **Important** This resource requires Vault Enterprise 2.2.0 or later.

## Example Usage

```hcl
resource "vault_auth_backend" "tpm" {
  type = "tpm"
  path = "tpm"
}

resource "vault_tpm_auth_backend_config" "tpm_config" {
  mount            = vault_auth_backend.tpm.path
  ca_lifetime      = "87600h"  # 10 years
  ca_soft_expiry   = "8760h"   # 1 year before hard expiry
  default_cert_ttl = "720h"    # 30 days
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).

* `mount` - (Required) Path of the enabled TPM auth backend mount to configure.

* `ca_lifetime` - (Optional) How long each CA is valid once it becomes active.
  Accepts duration format strings (e.g., "87600h", "10y"). If not specified, uses Vault's default.

* `ca_soft_expiry` - (Optional) How long before hard expiry the active CA stops signing new certificates.
  Accepts duration format strings (e.g., "8760h", "1y"). If not specified, uses Vault's default.

* `default_cert_ttl` - (Optional) Default lifetime for issued client certificates.
  Accepts duration format strings (e.g., "720h", "30d"). If not specified, uses Vault's default.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

TPM auth backend configuration can be imported using the resource's `id`.
In the case of the example above the `id` would be `auth/tpm/config`,
where the `tpm` component is the resource's `mount`, e.g.

```
$ terraform import vault_tpm_auth_backend_config.tpm_config auth/tpm/config
```
