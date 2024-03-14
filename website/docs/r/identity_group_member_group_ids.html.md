---
layout: "vault"
page_title: "Vault: vault_identity_group_member_group_ids resource"
sidebar_current: "docs-vault-resource-identity-group-member-group-ids"
description: |-
Manages member groups for an Identity Group for Vault.
---

# vault\_identity\_group\_member\_group\_ids

Manages member groups for an Identity Group for Vault. The
[Identity secrets engine](https://www.vaultproject.io/docs/secrets/identity/index.html)
is the identity management solution for Vault.

## Example Usage

### Exclusive Member Groups

```hcl
resource "vault_identity_group" "internal" {
  name                      = "internal"
  type                      = "internal"
  external_member_group_ids = true

  metadata = {
    version = "2"
  }
}

resource "vault_identity_group" "users" {
  name = "users"
  metadata = {
    version = "2"
  }
}

resource "vault_identity_group_member_group_ids" "members" {

  exclusive         = true
  member_group_ids = [vault_identity_group.users.id]
  group_id          = vault_identity_group.internal.id
}
```

### Non-Exclusive Member Groups

```hcl
resource "vault_identity_group" "internal" {
  name                      = "internal"
  type                      = "internal"
  external_member_group_ids = true

  metadata = {
    version = "2"
  }
}

resource "vault_identity_group" "users" {
  name = "users"
  metadata = {
    version = "2"
  }
}

resource "vault_identity_group_member_group_ids" "members" {

  exclusive         = false
  member_group_ids = [vault_identity_group.users.id]
  group_id          = vault_identity_group.internal.id
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `member_group_ids` - (Required) List of member groups that belong to the group

* `group_id` - (Required) Group ID to assign member entities to.

* `exclusive` - (Optional) Defaults to `true`.

  If `true`, this resource will take exclusive control of the member groups that belong to the group and will set
  it equal to what is specified in the resource.

  If set to `false`, this resource will simply ensure that the member groups specified in the resource are present 
  in the group. When destroying the resource, the resource will ensure that the member groups specified in the resource
  are removed.

## Attributes Reference

No additional attributes are exported by this resource.
