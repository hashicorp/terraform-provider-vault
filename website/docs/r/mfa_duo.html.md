---
layout: "vault"
page_title: "Vault: vault_mfa_duo resource"
sidebar_current: "docs-vault-resource-mfa-duo"
description: |-
  Managing the MFA Duo method configuration
---

# vault\_mfa-duo

Provides a resource to manage [Duo MFA](https://www.vaultproject.io/docs/enterprise/mfa/mfa-duo.html).

**Note** this feature is available only with Vault Enterprise.

## Example Usage

```hcl
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

resource "vault_mfa_duo" "my_duo" {
  name                  = "my_duo"
  mount_accessor        = vault_auth_backend.userpass.accessor
  secret_key            = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
  integration_key       = "BIACEUEAXI20BNWTEYXT"
  api_hostname          = "api-2b5c39f5.duosecurity.com"
}
```

## Argument Reference

The following arguments are supported:

- `name` `(string: <required>)` – Name of the MFA method.

- `mount_accessor` `(string: <required>)` - The mount to tie this method to for use in automatic mappings. The mapping will use the Name field of Aliases associated with this mount as the username in the mapping.

- `username_format` `(string)` - A format string for mapping Identity names to MFA method names. Values to substitute should be placed in `{{}}`. For example, `"{{alias.name}}@example.com"`. If blank, the Alias's Name field will be used as-is. Currently-supported mappings:
  - alias.name: The name returned by the mount configured via the `mount_accessor` parameter
  - entity.name: The name configured for the Entity
  - alias.metadata.`<key>`: The value of the Alias's metadata parameter
  - entity.metadata.`<key>`: The value of the Entity's metadata parameter

- `secret_key` `(string: <required>)` - Secret key for Duo.

- `integration_key` `(string: <required>)` - Integration key for Duo.

- `api_hostname` `(string: <required>)` - API hostname for Duo.

- `push_info` `(string)` - Push information for Duo.

## Import

Mounts can be imported using the `path`, e.g.

```
$ terraform import vault_mfa_duo.my_duo my_duo
```

