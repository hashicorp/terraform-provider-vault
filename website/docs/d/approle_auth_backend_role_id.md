---
layout: "vault"
page_title: "Vault: vault_approle_auth_backend_role_id data source"
sidebar_current: "docs-vault-datasource-approle-auth-backend-role-id"
description: |-
  Manages AppRole auth backend roles in Vault.
---

# vault\_approle\_auth\_backend\_role

Reads the Role ID of an AppRole from a Vault server.

## Example Usage

```hcl
data "vault_approle_auth_backend_role_id" "role" {
  backend   = "my-approle-backend"
  role_name = "my-role"
}

output "role-id" {
  value = data.vault_approle_auth_backend_role_id.role.role_id
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role to retrieve the Role ID for.

* `backend` - (Optional) The unique name for the AppRole backend the role to
  retrieve a RoleID for resides in. Defaults to "approle".

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `role_id` - The RoleID of the role.
