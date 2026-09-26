---
layout: "vault"
page_title: "Vault: vault_policy_acl data source"
sidebar_current: "docs-vault-datasource-policy-acl"
description: |-
  Reads an ACL policy in Vault.
---

# vault\_policy\_acl

This is a data source which can be used to fetch resources crated by `vault_policy`.

## Example Usage

```hcl
resource "vault_policy" "example" {
  name   = "example_policy"
  policy = data.vault_policy_document.example.hcl
}

data "vault_policy_acl" "example" {
  name   = "example"
}
```

## Argument Reference

* `name` - (Required) A name of Vault ACL policy to get.

## Attributes Reference

In addition to the above argument, the following attribute is exported:

* `policy` - Policy definition.
