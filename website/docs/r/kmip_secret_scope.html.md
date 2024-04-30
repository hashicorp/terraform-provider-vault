---
layout: "vault"
page_title: "Vault: vault_kmip_secret_scope resource"
sidebar_current: "docs-vault-resource-kmip-secret-scope"
description: |-
  Provision KMIP Secret scopes in Vault.
---

# vault\_kmip\_secret\_scope

Manages KMIP Secret Scopes in a Vault server. This feature requires
Vault Enterprise. See the [Vault documentation](https://www.vaultproject.io/docs/secrets/kmip)
for more information.

## Example Usage

```hcl
resource "vault_kmip_secret_backend" "default" {
  path         = "kmip"
  description  = "Vault KMIP backend"
}

resource "vault_kmip_secret_scope" "dev" {
  path  = vault_kmip_secret_backend.default.path
  scope = "dev"
  force = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) The unique path this backend should be mounted at. Must
  not begin or end with a `/`. Defaults to `kmip`.

* `scope` - (Required) Name of the scope.

* `force` - (Optional) Boolean field to force deletion even if there are managed objects in the scope.


## Attributes Reference

No additional attributes are exported by this resource.

## Import

KMIP Secret scope can be imported using the `path`, e.g.

```
$ terraform import vault_kmip_secret_scope.dev kmip
```
