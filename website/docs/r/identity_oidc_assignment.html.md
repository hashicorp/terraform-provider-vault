---
layout: "vault"
page_title: "Vault: vault_identity_oidc_assignment resource"
sidebar_current: "docs-vault-identity-oidc-assignment"
description: |-
    Provision OIDC Assignments in Vault.
---

# vault\_identity\_oidc\_assignment

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
    vault_identity_entity.test.id,
  ]
  group_ids  = [
    vault_identity_group.internal.id,
  ]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required) The name of the assignment.

* `entity_ids` - (Optional) A set of Vault entity IDs.

* `group_ids` - (Optional) A set of Vault group IDs.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

OIDC Assignments can be imported using the `name`, e.g.

```
$ terraform import vault_identity_oidc_assignment.default assignment
```
