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

```hcl
resource "vault_namespace" "ns1" {
  path = "ns1"
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) The path of the namespace. Must not have a trailing `/`

## Attributes Reference

* `id` - ID of the namespace.

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
