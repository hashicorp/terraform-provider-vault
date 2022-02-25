---
layout: "vault"
page_title: "Vault: vault_identity_oidc_assignment resource"
sidebar_current: "docs-vault-identity-oidc-assignment"
description: |-
    Provision OIDC Assignments in Vault.
---

# vault\_identity\_oidc\_scope

Manages OIDC Assignments in a Vault server. See the [Vault documentation](https://www.vaultproject.io/api-docs/secret/identity/oidc-provider#create-or-update-an-assignment)
for more information.

## Example Usage

```hcl
resource "vault_identity_group" "internal" {
  name     = "internal"
  type     = "internal"
  policies = ["dev", "test"]
}

resource "vault_identity_entity" "test" {
  name      = "test"
  policies  = ["test"]
}

resource "vault_identity_oidc_assignment" "default" {
  name       = "assignment"
  entity_ids = [
    vault_identity_entity.test.name,
  ]
  group_ids  = [
    vault_identity_group.internal.name,
  ]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the assignment.

* `entity_ids` - (Optional) A list of Vault entity IDs.

* `group_ids` - (Optional) A list of Vault group IDs.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

OIDC Assignments can be imported using the `name`, e.g.

```
$ terraform import vault_identity_oidc_assignment.default assignment
```
