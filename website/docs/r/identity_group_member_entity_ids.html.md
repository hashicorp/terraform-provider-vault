---
layout: "vault"
page_title: "Vault: vault_identity_group_member_entity_ids resource"
sidebar_current: "docs-vault-resource-identity-group-meber-entity-ids"
description: |-
  Manages member entities for an Identity Group for Vault.
---

# vault\_identity\_group\_member_entity_ids

Manages member entities for an Identity Group for Vault. The [Identity secrets engine](https://www.vaultproject.io/docs/secrets/identity/index.html) is the identity management solution for Vault.

## Example Usage

### Exclusive Member Entities

```hcl
resource "vault_identity_group" "internal" {
  name                        = "internal"
  type                        = "internal"
  external_member_entity_ids  = true

  metadata = {
    version = "2"
  }
}

resource "vault_identity_entity" "user" {
  name = "user"
}

resource "vault_identity_group_member_entity_ids" "members" {

  exclusive         = true
  member_entity_ids = [vault_identity_entity.user.id]
  group_id          = vault_identity_group.internal.id
}
```

### Non-exclusive Member Entities

```hcl
resource "vault_identity_group" "internal" {
  name                        = "internal"
  type                        = "internal"
  external_member_entity_ids  = true

  metadata = {
    version = "2"
  }
}

resource "vault_identity_entity" "test_user" {
  name = "test"
}

resource "vault_identity_entity" "second_test_user" {
  name = "second_test"
}

resource "vault_identity_entity" "dev_user" {
  name = "dev"
}

resource "vault_identity_group_member_entity_ids" "test" {
  member_entity_ids = [vault_identity_entity.test_user.id,
    vault_identity_entity.second_test_user.id]

  exclusive = false

  group_id = vault_identity_group.internal.id
}

resource "vault_identity_group_member_entity_ids" "others" {
  member_entity_ids = [vault_identity_entity.dev_user.id]

  exclusive = false

  group_id = vault_identity_group.internal.id
}
```

## Argument Reference

The following arguments are supported:

* `member_entity_ids` - (Required) List of member entities that belong to the group

* `group_id` - (Required) Group ID to assign member entities to.

* `exclusive` - (Optional) Defaults to `true`.

    If `true`, this resource will take exclusive control of the member entities that belong to the group and will set it equal to what is specified in the resource.

    If set to `false`, this resource will simply ensure that the member entities specified in the resource are present in the group. When destroying the resource, the resource will ensure that the member entities specified in the resource are removed.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `group_name` - The name of the group that are assigned the member entities.
