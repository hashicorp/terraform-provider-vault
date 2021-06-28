---
layout: "vault"
page_title: "Vault: vault_auth_backend_group resource"
sidebar_current: "docs-vault-resource-okta-auth-backend-group"
description: |-
  Managing groups in an Okta auth backend in Vault
---

# vault\_okta\_auth\_backend\_group

Provides a resource to create a group in an
[Okta auth backend within Vault](https://www.vaultproject.io/docs/auth/okta.html).

## Example Usage

```hcl
resource "vault_okta_auth_backend" "example" {
    path         = "group_okta"
    organization = "dummy"
}

resource "vault_okta_auth_backend_group" "foo" {
    path       = vault_okta_auth_backend.example.path
    group_name = "foo"
    policies   = ["one", "two"]
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) The path where the Okta auth backend is mounted

* `group_name` - (Required) Name of the group within the Okta

* `policies` - (Optional) Vault policies to associate with this group

## Attributes Reference

No additional attributes are exposed by this resource.

## Import

Okta authentication backend groups can be imported using the format `backend/groupName` e.g.

```
$ terraform import vault_okta_auth_backend_group.foo okta/foo
```
