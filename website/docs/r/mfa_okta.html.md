---
layout: "vault"
page_title: "Vault: vault_mfa_okta resource"
sidebar_current: "docs-vault-resource-mfa-okta"
description: |-
  Managing the MFA Okta method configuration
---

# vault\_mfa\_okta

Provides a resource to manage [Okta MFA](https://www.vaultproject.io/docs/enterprise/mfa/mfa-okta).

**Note** this feature is available only with Vault Enterprise.

## Example Usage

```hcl
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

resource "vault_mfa_okta" "my_okta" {
  name            = "my_okta"
  mount_accessor  = vault_auth_backend.userpass.accessor
  username_format = "user@example.com"
  org_name        = "hashicorp"
  api_token       = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
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

- `org_name` `(string: <required>)` - Name of the organization to be used in the Okta API.

- `api_token` `(string: <required>)` - Okta API key.

- `base_url` `(string)` - If set, will be used as the base domain for API requests. Examples are `okta.com`, 
  `oktapreview.com`, and `okta-emea.com`.

- `primary_email` `(string: <required>)` - If set to true, the username will only match the 
  primary email for the account.


## Attributes Reference

No additional attributes are exported by this resource.

## Import

Mounts can be imported using the `path`, e.g.

```
$ terraform import vault_mfa_okta.my_okta my_okta
```
