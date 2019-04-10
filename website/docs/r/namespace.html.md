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
