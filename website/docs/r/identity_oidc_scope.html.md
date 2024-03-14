---
layout: "vault"
page_title: "Vault: vault_identity_oidc_scope resource"
sidebar_current: "docs-vault-identity-oidc-scope"
description: |-
  Provision OIDC Scopes in Vault.
---

# vault\_identity\_oidc\_scope

Manages OIDC Scopes in a Vault server. See the [Vault documentation](https://www.vaultproject.io/api-docs/secret/identity/oidc-provider#create-or-update-a-scope)
for more information.

## Example Usage

```hcl
resource "vault_identity_oidc_scope" "groups" {
  name        = "groups"
  template    = "{\"groups\":{{identity.entity.groups.names}}}"
  description = "Vault OIDC Groups Scope"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required) The name of the scope. The `openid` scope name is reserved.

* `template` - (Optional) The template string for the scope. This may be provided as escaped JSON or base64 encoded JSON.

* `description` - (Optional) A description of the scope.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

OIDC Scopes can be imported using the `name`, e.g.

```
$ terraform import vault_identity_oidc_scope.groups groups
```
