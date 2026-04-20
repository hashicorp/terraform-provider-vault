---
layout: "vault"
page_title: "Vault: vault_password_policy resource"
sidebar_current: "docs-vault-resource-password-policy"
description: |-
  Writes Password policies for Vault
---

# vault\_password\_policy

Provides a resource to manage Password Policies 

**Note** this feature is available only Vault 1.5+ 

## Example Usage

```hcl
resource "vault_password_policy" "alphanumeric" {
  name = "alphanumeric"

  policy = <<EOT
    length = 20
    rule "charset" {
      charset = "abcdefghijklmnopqrstuvwxyz0123456789"
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

* `name` - (Required) The name of the password policy.

* `policy` - (Required) String containing a password policy.

* `entropy_source` - (Optional) Specifies an override to the default source of entropy (randomness) used to generate the passwords. Must be one of: `""`, `"platform"`, or `"seal"` (Vault Enterprise only). Requires Vault 1.21+.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Password policies can be imported using the `name`, e.g.

```
$ terraform import vault_password_policy.alphanumeric alphanumeric
```
