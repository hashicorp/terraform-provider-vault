---
layout: "vault"
page_title: "Vault: vault_identity_group_policies resource"
sidebar_current: "docs-vault-resource-identity-group-policies"
description: |-
  Manages policies for an Identity Group for Vault.
---

# vault\_identity\_group\_policies

Manages policies for an Identity Group for Vault. The [Identity secrets engine](https://www.vaultproject.io/docs/secrets/identity/index.html) is the identity management solution for Vault.

## Example Usage

### Exclusive Policies

```hcl
resource "vault_identity_group" "internal" {
  name     = "internal"
  type     = "internal"

  external_policies = true

  metadata = {
    version = "2"
  }
}

resource "vault_identity_group_policies" "policies" {
  policies = [
    "default",
    "test",
  ]

  exclusive = true

  group_id = vault_identity_group.internal.id
}
```

### Non-exclusive Policies

```hcl
resource "vault_identity_group" "internal" {
  name     = "internal"
  type     = "internal"

  external_policies = true

  metadata = {
    version = "2"
  }
}

resource "vault_identity_group_policies" "default" {
  policies = [
    "default",
    "test",
  ]

  exclusive = false

  group_id = vault_identity_group.internal.id
}

resource "vault_identity_group_policies" "others" {
  policies = [
    "others",
  ]

  exclusive = false

  group_id = vault_identity_group.internal.id
}
```

## Argument Reference

The following arguments are supported:

* `policies` - (Required) List of policies to assign to the group

* `group_id` - (Required) Group ID to assign policies to.

* `exclusive` - (Optional) Defaults to `true`.

    If `true`, this resource will take exclusive control of the policies assigned to the group and will set it equal to what is specified in the resource.

    If set to `false`, this resource will simply ensure that the policies specified in the resource are present in the group. When destroying the resource, the resource will ensure that the policies specified in the resource are removed.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `group_name` - The name of the group that are assigned the policies.
