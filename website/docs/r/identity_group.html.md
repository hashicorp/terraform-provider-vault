---
layout: "vault"
page_title: "Vault: vault_identity_group resource"
sidebar_current: "docs-vault-resource-identity-group"
description: |-
  Creates an Identity Group for Vault.
---

# vault\_identity\_group

Creates an Identity Group for Vault. The [Identity secrets engine](https://www.vaultproject.io/docs/secrets/identity/index.html) is the identity management solution for Vault.

A group can contain multiple entities as its members. A group can also have subgroups. Policies set on the group is granted to all members of the group. During request time, when the token's entity ID is being evaluated for the policies that it has access to; along with the policies on the entity itself, policies that are inherited due to group memberships are also granted.

## Example Usage

### Internal Group

```hcl
resource "vault_identity_group" "internal" {
  name     = "internal"
  type     = "internal"
  policies = ["dev", "test"]

  metadata = {
    version = "2"
  }
}
```

### External Group

```hcl
resource "vault_identity_group" "group" {
  name     = "external"
  type     = "external"
  policies = ["test"]

  metadata = {
    version = "1"
  }
}
```

## Caveats

It's important to note that Vault identity groups names are *case-insensitive*. For example the following resources would be equivalent.
Applying this configuration would result in the provider failing to create one of the identity groups, since the resources share the same `name`.

This sort of pattern should be avoided:
```hcl
resource "vault_identity_group" "internal" {
  # this duplicates the resource below
  name     = "internal"
  type     = "internal"
  policies = ["dev", "test"]

  metadata = {
    version = "2"
  }
}

resource "vault_identity_group" "Internal" {
  # this duplicates the resource above
  name     = "Internal"
  type     = "internal"
  policies = ["dev", "test"]

  metadata = {
    version = "2"
  }
}
```


## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required, Forces new resource) Name of the identity group to create.

* `type` - (Optional, Forces new resource) Type of the group, internal or external. Defaults to `internal`.

* `policies` - (Optional) A list of policies to apply to the group.

* `metadata` - (Optional) A Map of additional metadata to associate with the group.

* `member_group_ids` - (Optional) A list of Group IDs to be assigned as group members. Not allowed on `external` groups.

* `member_entity_ids` - (Optional) A list of Entity IDs to be assigned as group members. Not allowed on `external` groups.

* `external_policies` - (Optional) `false` by default. If set to `true`, this resource will ignore any policies returned from
  Vault or specified in the resource. You can use [`vault_identity_group_policies`](identity_group_policies.html) to manage
  policies for this group in a decoupled manner.

* `external_member_entity_ids` - (Optional) `false` by default. If set to `true`, this resource will ignore any Entity IDs
  returned from Vault or specified in the resource. You can use
  [`vault_identity_group_member_entity_ids`](identity_group_member_entity_ids.html) to manage Entity IDs for this group in a
  decoupled manner.

* `external_member_group_ids` - (Optional) `false` by default. If set to `true`, this resource will ignore any Group IDs
  returned from Vault or specified in the resource. You can use
  [`vault_identity_group_member_group_ids`](identity_group_member_group_ids.html) to manage Group IDs for this group in a
  decoupled manner.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The `id` of the created group.

## Import

Identity group can be imported using the `id`, e.g.

```
$ terraform import vault_identity_group.test 'fcbf1efb-2b69-4209-bed8-811e3475dad3'
```
