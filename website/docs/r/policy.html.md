---
layout: "vault"
page_title: "Vault: vault_policy resource"
sidebar_current: "docs-vault-resource-policy"
description: |-
  Writes arbitrary policies for Vault
---

# vault\_policy


## Example Usage

```hcl
resource "vault_policy" "example" {
  name = "dev-team"

  policy = <<EOT
path "secret/my_app" {
  capabilities = ["update"]
}
EOT
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required) The name of the policy

* `policy` - (Required) String containing a Vault policy

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Policies can be imported using the `name`, e.g.

```
$ terraform import vault_policy.example dev-team
```

## Tutorials 

Refer to the following tutorials for additional usage examples:

- [Codify Management of Vault Enterprise Using Terraform](https://learn.hashicorp.com/tutorials/vault/codify-mgmt-enterprise)

- [Codify Management of Vault Using Terraform](https://learn.hashicorp.com/tutorials/vault/codify-mgmt-oss)
