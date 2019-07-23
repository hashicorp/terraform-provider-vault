---
layout: "vault"
page_title: "Vault: vault_azure_auth_backend_role resource"
sidebar_current: "docs-vault-resource-azure-auth-backend-role"
description: |-
  Manages Azure auth backend roles in Vault.
---

# vault\_azure\_auth\_backend\_role

Manages an Azure auth backend role in a Vault server. Roles constrain the
instances or principals that can perform the login operation against the
backend. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/azure.html) for more
information.

## Example Usage

```hcl
resource "vault_auth_backend" "azure" {
  type = "azure"
}

resource "vault_azure_auth_backend_role" "example" {
  backend                         = "${vault_auth_backend.azure.path}"
  role                            = "test-role"
  bound_subscription_ids          = ["11111111-2222-3333-4444-555555555555"]
  bound_resource_groups           = ["123456789012"]
  ttl                             = 60
  max_ttl                         = 120
  policies                        = ["default", "dev", "prod"]
}
```

## Argument Reference

The following arguments are supported:

* `role` - (Required) The name of the role.

* `bound_service_principal_ids` - (Optional) If set, defines a constraint on the
  service principals that can perform the login operation that they should be possess
  the ids specified by this field.

* `bound_group_ids` - (Optional) If set, defines a constraint on the groups
  that can perform the login operation that they should be using the group
   ID specified by this field.

* `bound_locations` - (Optional) If set, defines a constraint on the virtual machines
  that can perform the login operation that the location in their identity
  document must match the one specified by this field.

* `bound_subscription_ids` - (Optional) If set, defines a constraint on the subscriptions
  that can perform the login operation to ones which  matches the value specified by this
  field.

* `bound_resource_groups` - (Optional) If set, defines a constraint on the virtual
  machiness that can perform the login operation that they be associated with
  the resource group that matches the value specified by this field.

* `bound_scale_sets` - (Optional) If set, defines a constraint on the virtual
  machines that can perform the login operation that they must match the scale set
  specified by this field.

* `ttl` - (Optional) The TTL period of tokens issued using this role, provided
  as a number of seconds.

* `max_ttl` - (Optional) The maximum allowed lifetime of tokens issued using
  this role, provided as a number of seconds.

* `period` - (Optional) If set, indicates that the token generated using this
  role should never expire. The token should be renewed within the duration
  specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. The maximum allowed lifetime of token issued using this
  role. Specified as a number of seconds.

* `policies` - (Optional) An array of strings specifying the policies to be set
  on tokens issued using this role.


## Attributes Reference

No additional attributes are exported by this resource.

## Import

Azure auth backend roles can be imported using `auth/`, the `backend` path, `/role/`, and the `role` name e.g.

```
$ terraform import vault_azure_auth_backend_role.example auth/azure/role/test-role
```
