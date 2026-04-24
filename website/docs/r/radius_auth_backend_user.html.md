---
layout: "vault"
page_title: "Vault: vault_radius_auth_backend_user resource"
sidebar_current: "docs-vault-resource-radius-auth-backend-user"
description: |-
  Managing users in a RADIUS auth backend in Vault
---

# vault\_radius\_auth\_backend\_user

Provides a resource to create a user in a [RADIUS auth backend within Vault](https://www.vaultproject.io/docs/auth/radius.html).

## Example Usage

```hcl
resource "vault_auth_backend" "radius" {
    type = "radius"
    path = "radius"
}

resource "vault_radius_auth_backend_user" "user" {
    mount    = vault_auth_backend.radius.path
    username = "test-user"
    policies = ["default", "dev-policy"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `mount` - (Required) Path to the RADIUS auth mount where the user will be registered.

* `username` - (Required) The username to register with the RADIUS auth backend.

* `policies` - (Optional) A set of Vault policies to associate with this user. If not set, only the `default` policy will be applicable to the user.

For more details on the usage of each argument consult the [Vault RADIUS API documentation](https://developer.hashicorp.com/vault/api-docs/auth/radius).

## Attribute Reference

No additional attributes are exposed by this resource.

## Import

RADIUS authentication backend users can be imported using the full user API path, e.g.

```
$ terraform import vault_radius_auth_backend_user.user auth/radius/users/test-user
```
