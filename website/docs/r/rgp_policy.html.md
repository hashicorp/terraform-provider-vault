---
layout: "vault"
page_title: "Vault: vault_rgp_policy resource"
sidebar_current: "docs-vault-resource-rgp-policy"
description: |-
  Writes Sentinel role governing policies for Vault
---

# vault\_rgp\_policy

Provides a resource to manage Role Governing Policy (RGP) via [Sentinel](https://www.vaultproject.io/docs/enterprise/sentinel/index.html).

**Note** this feature is available only with Vault Enterprise.

## Example Usage

```hcl
resource "vault_rgp_policy" "allow-all" {
  name              = "allow-all"
  enforcement_level = "soft-mandatory"

  policy = <<EOT
main = rule {
  true
}
EOT
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required) The name of the policy

* `enforcement_level` - (Required) Enforcement level of Sentinel policy. Can be either `advisory` or `soft-mandatory` or `hard-mandatory`

* `policy` - (Required) String containing a Sentinel policy

## Attributes Reference

No additional attributes are exported by this resource.
