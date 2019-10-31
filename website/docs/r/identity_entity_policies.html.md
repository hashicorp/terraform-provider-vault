---
layout: "vault"
page_title: "Vault: vault_identity_entity_policies resource"
sidebar_current: "docs-vault-resource-identity-entity-policies"
description: |-
  Manages policies for an Identity Entity for Vault.
---

# vault\_identity\_entity\_policies

Manages policies for an Identity Entity for Vault. The [Identity secrets engine](https://www.vaultproject.io/docs/secrets/identity/index.html) is the identity management solution for Vault.

## Example Usage

### Exclusive Policies

```hcl
resource "vault_identity_entity" "entity" {
  name              = "entity"
  external_policies = true
}

resource "vault_identity_entity_policies" "policies" {
  policies = [
    "default",
    "test",
  ]

  exclusive = true

  entity_id = vault_identity_entity.entity.id
}
```

### Non-exclusive Policies

```hcl
resource "vault_identity_entity" "entity" {
  name              = "entity"
  external_policies = true
}

resource "vault_identity_entity_policies" "default" {
  policies = [
    "default",
    "test",
  ]

  exclusive = false

  entity_id = vault_identity_entity.entity.id
}

resource "vault_identity_entity_policies" "others" {
  policies = [
    "others",
  ]

  exclusive = false

  entity_id = vault_identity_entity.entity.id
}
```

## Argument Reference

The following arguments are supported:

* `policies` - (Required) List of policies to assign to the entity

* `entity_id` - (Required) Entity ID to assign policies to.

* `exclusive` - (Optional) Defaults to `true`.

    If `true`, this resource will take exclusive control of the policies assigned to the entity and will set it equal to what is specified in the resource.

    If set to `false`, this resource will simply ensure that the policies specified in the resource are present in the entity. When destroying the resource, the resource will ensure that the policies specified in the resource are removed.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `entity_name` - The name of the entity that are assigned the policies.
