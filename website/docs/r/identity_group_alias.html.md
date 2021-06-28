---
layout: "vault"
page_title: "Vault: vault_identity_group_alias resource"
sidebar_current: "docs-vault-resource-identity-group-alias"
description: |-
  Creates an Identity Group Alias for Vault.
---

# vault\_identity\_group\_alias

Creates an Identity Group Alias for Vault. The [Identity secrets engine](https://www.vaultproject.io/docs/secrets/identity/index.html) is the identity management solution for Vault.

Group aliases allows entity membership in external groups to be managed semi-automatically. External group serves as a mapping to a group that is outside of the identity store. External groups can have one (and only one) alias. This alias should map to a notion of group that is outside of the identity store. For example, groups in LDAP, and teams in GitHub. A username in LDAP, belonging to a group in LDAP, can get its entity ID added as a member of a group in Vault automatically during logins and token renewals. This works only if the group in Vault is an external group and has an alias that maps to the group in LDAP. If the user is removed from the group in LDAP, that change gets reflected in Vault only upon the subsequent login or renewal operation.

## Example Usage

```hcl
resource "vault_identity_group" "group" {
  name     = "test"
  type     = "external"
  policies = ["test"]
}

resource "vault_auth_backend" "github" {
  type = "github"
  path = "github"
}

resource "vault_identity_group_alias" "group-alias" {
  name           = "Github_Team_Slug"
  mount_accessor = vault_auth_backend.github.accessor
  canonical_id   = vault_identity_group.group.id
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required, Forces new resource) Name of the group alias to create.

* `mount_accessor` - (Required) Mount accessor of the authentication backend to which this alias belongs to.

* `canonical_id` - (Required) ID of the group to which this is an alias.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The `id` of the created group alias.

## Import

Group aliases can be imported using the uuid of the alias record, e.g.

```shell
terraform import vault_identity_group_alias.alias_name 63104e20-88e4-11eb-8d04-cf7ac9d60157
```
