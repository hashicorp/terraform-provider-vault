---
layout: "vault"
page_title: "Vault: vault_mfa_pingid resource"
sidebar_current: "docs-vault-resource-mfa-pingid"
description: |-
  Managing the MFA PingID method configuration
---

# vault\_mfa\_pingid

Provides a resource to manage [PingID MFA](https://www.vaultproject.io/docs/enterprise/mfa/mfa-pingid).

**Note** this feature is available only with Vault Enterprise.

## Example Usage

```hcl
variable "settings_file" {}

resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

resource "vault_mfa_pingid" "my_pingid" {
  name                 = "my_pingid"
  mount_accessor       = vault_auth_backend.userpass.accessor
  username_format      = "user@example.com"
  settings_file_base64 = var.settings_file
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

- `name` `(string: <required>)` – Name of the MFA method.

- `mount_accessor` `(string: <required>)` - The mount to tie this method to for use in automatic mappings. 
  The mapping will use the Name field of Aliases associated with this mount as the username in the mapping.

- `username_format` `(string)` - A format string for mapping Identity names to MFA method names. 
  Values to substitute should be placed in `{{}}`. For example, `"{{alias.name}}@example.com"`. 
  If blank, the Alias's Name field will be used as-is. Currently-supported mappings:
    - alias.name: The name returned by the mount configured via the `mount_accessor` parameter
    - entity.name: The name configured for the Entity
    - alias.metadata.`<key>`: The value of the Alias's metadata parameter
    - entity.metadata.`<key>`: The value of the Entity's metadata parameter

- `settings_file_base64` `(string: <required>)` - A base64-encoded third-party settings file retrieved
  from PingID's configuration page.

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

- `idp_url` `(string)` – IDP URL computed by Vault

- `admin_url` `(string)` – Admin URL computed by Vault

- `authenticator_url` `(string)` – Authenticator URL computed by Vault

- `org_alias` `(string)` – Org Alias computed by Vault

- `id` `(string)` – ID computed by Vault

- `namespace_id` `(string)` – Namespace ID computed by Vault

- `type` `(string)` – Type of configuration computed by Vault

- `use_signature` `(string)` – If set to true, enables use of PingID signature. Computed by Vault


## Import

Mounts can be imported using the `path`, e.g.

```
$ terraform import vault_mfa_pingid.my_pingid my_pingid
```
