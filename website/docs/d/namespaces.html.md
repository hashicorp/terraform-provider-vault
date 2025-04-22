---
layout: "vault"
page_title: "Vault: vault_namespaces data source"
sidebar_current: "docs-vault-datasource-namespaces"
description: |-
  List of all child namespaces in Vault
---

# vault\_namespace

Lists all child [Namespaces](https://developer.hashicorp.com/vault/docs/enterprise/namespaces) in Vault.

**Note** this feature is available only with Vault Enterprise.

## Example Usage

### Direct child namespaces

```hcl
data "vault_namespaces" "children" {}
```

### All child namespaces

```hcl
data "vault_namespaces" "children" {
  recursive = true
}
```

### Child namespace details

To fetch the details of child namespaces:

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
* `recursive` - (Optional) If `true`, it will returns all child namespaces of the given namespace. Defaults to `false`, which returns only direct child namespaces.

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `paths` - Set of the paths of child namespaces.
* `paths_fq` - Set of the fully qualified paths of child namespaces.
