---
layout: "vault"
page_title: "Vault: vault_namespace resource"
sidebar_current: "docs-vault-resource-namespace"
description: |-
  Writes namespaces for Vault
---

# vault\_namespace

Provides a resource to manage [Namespaces](https://www.vaultproject.io/docs/enterprise/namespaces/index.html).

**Note** this feature is available only with Vault Enterprise.

## Example Usage

### Single namespace

```hcl
resource "vault_namespace" "ns1" {
  path = "ns1"
}
```

### Nested namespaces

```hcl
provider "vault" {}

variable "child_namespaces" {
  default = [
    "child_0",
    "child_1",
    "child_2",
  ]
}

locals {
  child_namespaces = toset(var.child_namespaces)
}

resource "vault_namespace" "parent" {
  path = "parent"
}

resource "vault_namespace" "children" {
  for_each  = local.child_namespaces
  namespace = vault_namespace.parent.path
  path      = each.key
}

resource "vault_mount" "children" {
  for_each  = local.child_namespaces
  namespace = vault_namespace.children[each.key].path_fq
  path      = "secrets"
  type      = "kv"
  options = {
    version = "1"
  }
}

resource "vault_generic_secret" "children" {
  for_each  = local.child_namespaces
  namespace = vault_mount.children[each.key].namespace
  path      = "${vault_mount.children[each.key].path}/secret"
  data_json = jsonencode(
    {
      "ns" = each.key
    }
  )
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) The path of the namespace. Must not have a trailing `/`

## Attributes Reference

* `id` - ID of the namespace.

* `path_fq` - The fully qualified path to the namespace. Useful when provisioning resources in a child `namespace`.

## Import

Namespaces can be imported using its `name` as accessor id

```
$ terraform import vault_namespace.example <name>
```

If the declared resource is imported and intends to support namespaces using a provider alias, then the name is relative to the namespace path.

```

provider "vault" {
  # Configuration options
  namespace = "example"
  alias     = "example"
}

resource vault_namespace "example2" {
  provider = vault.example
}

$ terraform import vault_namespace.example2 example2

$ terraform state show vault_namespace.example2
# vault_namespace.example2
resource "vault_namespace" "example2" {
    id           = "example/example2/"
    namespace_id = <known after import>
    path         = "example2"
}
```

## Tutorials

Refer to the [Codify Management of Vault Enterprise Using Terraform](https://learn.hashicorp.com/tutorials/vault/codify-mgmt-enterprise) tutorial for additional examples using Vault namespaces.
