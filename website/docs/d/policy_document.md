---
layout: "vault"
page_title: "Vault: vault_policy_document data source"
sidebar_current: "docs-vault-datasource-policy-document"
description: |-
  Generates an Vault policy document in HCL format.
---

# vault\_policy\_document

This is a data source which can be used to construct a HCL representation of an Vault policy document, for use with resources which expect policy documents, such as the `vault_policy` resource.

## Example Usage

```hcl
data "vault_policy_document" "example" {
  rule {
    path         = "secret/*"
    capabilities = ["create", "read", "update", "delete", "list"]
    description  = "allow all on secrets"
  }
}

resource "vault_policy" "example" {
  name   = "example_policy"
  policy = "${data.vault_policy_document.hcl}"
}
```

## Argument Reference

Each document configuration may have one or more `rule` blocks, which each accept the following arguments:

* `path` - (Required) A path in Vault that this rule applies to.

* `capabilities` - (Required) A list of capabilities that this rule apply to `path`. For example, ["read", "write"].

* `description` - (Optional) Description of the rule. Will be added as a commend to rendered rule.

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `hcl` - The above arguments serialized as a standard Vault HCL policy document.
