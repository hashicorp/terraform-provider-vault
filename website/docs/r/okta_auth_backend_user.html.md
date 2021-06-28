---
layout: "vault"
page_title: "Vault: vault_auth_backend_user resource"
sidebar_current: "docs-vault-resource-okta-auth-backend-user"
description: |-
  Managing users in an Okta auth backend in Vault
---

# vault\_okta\_auth\_backend\_user

Provides a resource to create a user in an
[Okta auth backend within Vault](https://www.vaultproject.io/docs/auth/okta.html).

## Example Usage

```hcl
resource "vault_okta_auth_backend" "example" {
    path         = "user_okta"
    organization = "dummy"
}

resource "vault_okta_auth_backend_user" "foo" {
    path     = vault_okta_auth_backend.example.path
    username = "foo"
    groups   = ["one", "two"]
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) The path where the Okta auth backend is mounted

* `username` - (Required Optional) Name of the user within Okta

* `groups` - (Optional) List of Okta groups to associate with this user

* `policies` - (Optional) List of Vault policies to associate with this user

## Attributes Reference

No additional attributes are exposed by this resource.
