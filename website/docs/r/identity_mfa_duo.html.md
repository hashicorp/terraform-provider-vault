---
layout: "vault"
page_title: "Vault: vault_identity_mfa_duo resource"
sidebar_current: "docs-vault-resource-identity-mfa-duo"
description: |-
  Resource for configuring the duo MFA method.
---

# vault_identity_mfa_duo

Resource for configuring the duo MFA method.

## Example Usage


```hcl
resource "vault_identity_mfa_duo" "example" {
  api_hostname    = "api-xxxxxxxx.duosecurity.com"
  secret_key      = "secret-key"
  integration_key = "secret-int-key"
}
```
## Argument Reference

The following arguments are supported:

* `api_hostname` - (Required) API hostname for Duo
* `integration_key` - (Required) Integration key for Duo
* `secret_key` - (Required) Secret key for Duo
* `mount_accessor` - (Optional) Mount accessor.
* `namespace` - (Optional) Target namespace. (requires Enterprise)
* `push_info` - (Optional) Push information for Duo.
* `use_passcode` - (Optional) Require passcode upon MFA validation.
* `username_format` - (Optional) A template string for mapping Identity names to MFA methods.
* `uuid` - (Optional) Resource UUID.

## Attributes Reference


In addition to the fields above, the following attributes are exported:

* `method_id` - Method ID.
* `namespace_id` - Method's namespace ID.
* `namespace_path` - Method's namespace path.
* `type` - MFA type.

## Import

Resource can be imported using its `uuid` field, e.g.

```
$ terraform import vault_identity_mfa_duo.example 0d89c36a-4ff5-4d70-8749-bb6a5598aeec
```
