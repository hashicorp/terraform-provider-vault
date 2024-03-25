---
layout: "vault"
page_title: "Vault: vault_namespace data source"
sidebar_current: "docs-vault-datasource-namespace"
description: |-
  Reads namespace information from Vault
---

# vault\_namespace

Lookup a [Namespace](https://developer.hashicorp.com/vault/docs/enterprise/namespaces) from Vault or from the provider configuration.

**Note** this feature is available only with Vault Enterprise.

## Example Usage

### Current namespace

```hcl
data "vault_namespace" "current" {}
```

### Single namespace

```hcl
data "vault_namespace" "ns1" {
  path = "ns1"
}
```

### Nested namespace

```hcl
provider "vault" {
  namespace = "foo"
}

data "vault_namespace" "child" {
  namespace = "parent"
  path      = "child"
}

locals {
  full_path = data.vault_namespace.child.id      # -> foo/parent/child/
  path_fq   = data.vault_namespace.child.path_fq # -> parent/child
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).

* `path` - (Optional) The path of the namespace. Must not have a trailing `/`.
  If not specified or empty, path attributes are set for the current namespace
  based on the `namespace` arguments of the provider and this data source.
  Other path related attributes will be empty in this case.

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `id` - The fully qualified path to the namespace, including the provider `namespace` and a trailing slash.

* `path_fq` - The fully qualified path to the namespace. Useful when provisioning resources in a child `namespace`.
  The path is relative to the provider's `namespace` argument.

* `namespace_id` - Vault server's internal ID of the namespace.
  Only fetched if `path` is specified.

* `custom_metadata` - (Optional) A map of strings containing arbitrary metadata for the namespace.
  Only fetched if `path` is specified.
  *Requires Vault 1.12+.*

