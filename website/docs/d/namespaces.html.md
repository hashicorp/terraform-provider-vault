---
layout: "vault"
page_title: "Vault: vault_namespaces data souece"
sidebar_current: "docs-vault-datasource-namespaces"
description: |-
  Fetches a list of all namespaces in Vault
---

# vault\_namespace

Lists all direct child [Namespaces](https://www.vaultproject.io/docs/enterprise/namespaces/index.html) in Vault.

**Note** this feature is available only with Vault Enterprise.

## Example Usage

### Child namespaces

```hcl
data "vault_namespaces" "children" {}
```

### Nested namespace

To fetch the details of nested namespaces:

```hcl
data "vault_namespaces" "children" {
  namespace = "parent"
}

data "vault_namespace" "child" {
  for_each  = data.vault_namespaces.children.paths
  namespace = data.vault_namespaces.children.namespace
  path      = each.key
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `paths` - Set of the paths of direct child namespaces.
