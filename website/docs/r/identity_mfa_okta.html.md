---
layout: "vault"
page_title: "Vault: vault_identity_mfa_okta resource"
sidebar_current: "docs-vault-resource-identity-mfa-okta"
description: |-
  Resource for configuring the okta MFA method.
---

# vault_identity_mfa_okta

Resource for configuring the okta MFA method.

## Example Usage


```hcl
resource "vault_identity_mfa_okta" "example" {
  org_name        = "org1"
  api_token       = "token1"
  base_url        = "qux.baz.com"
}
```
## Argument Reference

The following arguments are supported:

* `api_token` - (Required) Okta API token.
* `org_name` - (Required) Name of the organization to be used in the Okta API.
* `base_url` - (Optional) The base domain to use for API requests.
* `mount_accessor` - (Optional) Mount accessor.
* `namespace` - (Optional) Target namespace. (requires Enterprise)
* `primary_email` - (Optional) Only match the primary email for the account.
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
$ terraform import vault_identity_mfa_okta.example 0d89c36a-4ff5-4d70-8749-bb6a5598aeec
```
