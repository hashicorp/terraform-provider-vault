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
  policy = data.vault_policy_document.example.hcl
}
```

## Argument Reference

Each document configuration may have one or more `rule` blocks, which each accept the following arguments:

* `path` - (Required) A path in Vault that this rule applies to.

* `capabilities` - (Required) A list of capabilities that this rule apply to `path`. For example, ["read", "write"].

* `description` - (Optional) Description of the rule. Will be added as a comment to rendered rule.

* `required_parameters` - (Optional) A list of parameters that must be specified.

* `allowed_parameter` - (Optional) Whitelists a list of keys and values that are permitted on the given path. See [Parameters](#Parameters) below.

* `denied_parameter` - (Optional) Blacklists a list of parameter and values. Any values specified here take precedence over `allowed_parameter`. See [Parameters](#Parameters) below.

* `min_wrapping_ttl` - (Optional) The minimum allowed TTL that clients can specify for a wrapped response.

* `max_wrapping_ttl` - (Optional) The maximum allowed TTL that clients can specify for a wrapped response.

### Parameters

Each of `*_parameter` attributes can optionally further restrict paths based on the keys and data at those keys when evaluating the permissions for a path.

Support the following arguments:

* `key` - (Required) name of permitted or denied parameter.

* `value` - (Required) list of values what are permitted or denied by policy rule.

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `hcl` - The above arguments serialized as a standard Vault HCL policy document.
