---
layout: "vault"
page_title: "Vault: vault_identity_mfa_pingid resource"
sidebar_current: "docs-vault-resource-identity-mfa-pingid"
description: |-
  Resource for configuring the pingid MFA method.
---

# vault_identity_mfa_pingid

Resource for configuring the pingid MFA method.

## Example Usage


```hcl
resource "vault_identity_mfa_pingid" "example" {
  settings_file_base64 = "CnVzZV9iYXNlNjR[...]HBtCg=="
}
```
## Argument Reference

The following arguments are supported:

* `settings_file_base64` - (Required) A base64-encoded third-party settings contents as retrieved from PingID's configuration page.
* `admin_url` - (Optional) The admin URL, derived from "settings_file_base64"
* `authenticator_url` - (Optional) A unique identifier of the organization, derived from "settings_file_base64"
* `idp_url` - (Optional) The IDP URL, derived from "settings_file_base64"
* `mount_accessor` - (Optional) Mount accessor.
* `namespace` - (Optional) Target namespace. (requires Enterprise)
* `org_alias` - (Optional) The name of the PingID client organization, derived from "settings_file_base64"
* `use_signature` - (Optional) Use signature value, derived from "settings_file_base64"
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
$ terraform import vault_identity_mfa_pingid.example 0d89c36a-4ff5-4d70-8749-bb6a5598aeec
```
