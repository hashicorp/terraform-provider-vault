---
layout: "vault"
page_title: "Vault: vault_identity_mfa_login_enforcement resource"
sidebar_current: "docs-vault-resource-identity-mfa-login-enforcement"
description: |-
  Resource for configuring MFA login-enforcement
---

# vault_identity_mfa_login_enforcement

Resource for configuring MFA login-enforcement

## Example Usage


```hcl
resource "vault_identity_mfa_duo" "example" {
  secret_key      = "secret-key"
  integration_key = "int-key"
  api_hostname    = "foo.baz"
  push_info       = "push-info"
}

resource "vault_identity_mfa_login_enforcement" "example" {
  name = "default"
  mfa_method_ids = [
    vault_identity_mfa_duo.example.method_id,
  ]
}
```
## Argument Reference

The following arguments are supported:

* `mfa_method_ids` - (Required) Set of MFA method UUIDs.
* `name` - (Required) Login enforcement name.
* `auth_method_accessors` - (Optional) Set of auth method accessor IDs.
* `auth_method_types` - (Optional) Set of auth method types.
* `identity_entity_ids` - (Optional) Set of identity entity IDs.
* `identity_group_ids` - (Optional) Set of identity group IDs.
* `namespace` - (Optional) Target namespace. (requires Enterprise)
* `uuid` - (Optional) Resource UUID.

## Attributes Reference


In addition to the fields above, the following attributes are exported:

* `namespace_id` - Method's namespace ID.
* `namespace_path` - Method's namespace path.

## Import

Resource can be imported using its `name` field, e.g.

```
$ terraform import vault_identity_mfa_login_enforcement.example default
```
