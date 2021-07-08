---
layout: "vault"
page_title: "Vault: vault_egp_policy resource"
sidebar_current: "docs-vault-resource-egp-policy"
description: |-
  Writes Sentinel endpoint governing policies for Vault
---

# vault\_egp\_policy

Provides a resource to manage Endpoint Governing Policy (EGP) via [Sentinel](https://www.vaultproject.io/docs/enterprise/sentinel/index.html).

**Note** this feature is available only with Vault Enterprise.


## Example Usage

```hcl
resource "vault_egp_policy" "allow-all" {
  name              = "allow-all"
  paths             = ["*"]
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

* `name` - (Required) The name of the policy

* `paths` - (Required) List of paths to which the policy will be applied to

* `enforcement_level` - (Required) Enforcement level of Sentinel policy. Can be either `advisory` or `soft-mandatory` or `hard-mandatory`

* `policy` - (Required) String containing a Sentinel policy

## Attributes Reference

No additional attributes are exported by this resource.
