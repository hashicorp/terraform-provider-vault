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
  backend                         = vault_auth_backend.azure.path
  role                            = "test-role"
  bound_subscription_ids          = ["11111111-2222-3333-4444-555555555555"]
  bound_resource_groups           = ["123456789012"]
  token_ttl                       = 60
  token_max_ttl                   = 120
  token_policies                  = ["default", "dev", "prod"]
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

### Common Token Arguments

These arguments are common across several Authentication Token resources since Vault 1.2.

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_period` - (Optional) If set, indicates that the
  token generated using this role should never expire. The token should be renewed within the
  duration specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. Specified in seconds.

* `token_policies` - (Optional) List of policies to encode onto generated tokens. Depending
  on the auth method, this list may be supplemented by user/group/other values.

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks of IP
  addresses which can authenticate successfully, and ties the resulting token to these blocks
  as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an
  [explicit max TTL](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token in number of seconds. This is a hard cap even if `token_ttl` and
  `token_max_ttl` would otherwise allow a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on
  generated tokens; otherwise it will be added to the policies set in token_policies.

* `token_num_uses` - (Optional) The
  [period](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls),
  if any, in number of seconds to set on the token.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

### Deprecated Arguments

These arguments are deprecated since Vault 1.2 in favour of the common token arguments
documented above.

* `ttl` - (Optional; Deprecated, use `token_ttl` instead if you are running Vault >= 1.2) The TTL period of tokens issued
  using this role, provided as a number of seconds.

* `max_ttl` - (Optional; Deprecated, use `token_max_ttl` instead if you are running Vault >= 1.2) The maximum allowed lifetime of tokens
  issued using this role, provided as a number of seconds.

* `policies` - (Optional; Deprecated, use `token_policies` instead if you are running Vault >= 1.2) An array of strings
  specifying the policies to be set on tokens issued using this role.

* `period` - (Optional; Deprecated, use `token_period` instead if you are running Vault >= 1.2) If set, indicates that the
  token generated using this role should never expire. The token should be renewed within the
  duration specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. Specified in seconds.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Azure auth backend roles can be imported using `auth/`, the `backend` path, `/role/`, and the `role` name e.g.

```
$ terraform import vault_azure_auth_backend_role.example auth/azure/role/test-role
```
