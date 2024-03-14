---
layout: "vault"
page_title: "Vault: vault_auth_backends data source"
sidebar_current: "docs-vault-datasource-auth-backends"
description: |-
  List Auth Backends from Vault
---

# vault\_auth\_backends

## Example Usage

```hcl
data "vault_auth_backends" "example" {}
```

```hcl
data "vault_auth_backends" "example-filter" {
  type = "kubernetes"
}

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `type` - (Optional) The name of the auth method type. Allows filtering of backends returned by type.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `accessors` - The accessor IDs for the auth methods.

* `paths` - List of auth backend mount points.
