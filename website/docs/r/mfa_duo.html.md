---
layout: "vault"
page_title: "Vault: vault_mfa_duo resource"
sidebar_current: "docs-vault-resource-mfa-duo"
description: |-
  Managing the MFA Duo method configuration
---

# vault\_mfa-duo

Provides a resource to manage [Duo MFA](https://www.vaultproject.io/api-docs/secret/identity/mfa/duo).

## Example Usage

```hcl
resource "vault_mfa_duo" "my_duo" {
  secret_key            = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
  integration_key       = "BIACEUEAXI20BNWTEYXT"
  api_hostname          = "api-2b5c39f5.duosecurity.com"
}
```

## Argument Reference

The following arguments are supported:

- `username_format` `(string)` - A format string for mapping Identity names to MFA method names. Values to substitute should be placed in `{{}}`. For example, `"{{alias.name}}@example.com"`. If blank, the Alias's Name field will be used as-is. Currently-supported mappings:
  - alias.name: The name returned by the mount configured via the `mount_accessor` parameter
  - entity.name: The name configured for the Entity
  - alias.metadata.`<key>`: The value of the Alias's metadata parameter
  - entity.metadata.`<key>`: The value of the Entity's metadata parameter

- `secret_key` `(string: <required>)` - Secret key for Duo.

- `integration_key` `(string: <required>)` - Integration key for Duo.

- `api_hostname` `(string: <required>)` - API hostname for Duo.

- `push_info` `(string)` - Push information for Duo.

- `use_passcode` `(bool)` - If true, the user is reminded to use the passcode upon MFA validation.

## Attributes Reference

* `id` - ID of the Duo MFA method.

## Import

Mounts can be imported using the `id`, e.g.

```
$ terraform import vault_mfa_duo.my_duo "3856fb4d-3c91-dcaf-2401-68f446796bfb"
```

