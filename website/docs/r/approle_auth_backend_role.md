---
layout: "vault"
page_title: "Vault: vault_approle_auth_backend_role resource"
sidebar_current: "docs-vault-approle-auth-backend-role"
description: |-
  Manages AppRole auth backend roles in Vault.
---

# vault\_approle\_auth\_backend\_role

Manages an AppRole auth backend role in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/approle.html) for more
information.

## Example Usage

```hcl
resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "example" {
  backend   = "${vault_auth_backend.approle.path}"
  role_name = "test-role"
  policies  = ["default", "dev", "prod"]
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role.

* `role_id` - (Optional) The RoleID of this role. If not specified, one will be
  auto-generated.

* `bind_secret_id` - (Optional) Whether or not to require `secret_id` to be
  presented when logging in using this AppRole. Defaults to `true`.

* `bound_cidr_list` - (Optional) If set, specifies blocks of IP addresses which
  can perform the login operation.

* `policies` - (Optional) An array of strings specifying the policies to be set
  on tokens issued using this role.

* `secret_id_num_uses` - (Optional) The number of times any particular SecretID
  can be used to fetch a token from this AppRole, after which the SecretID will
  expire. A value of zero will allow unlimited uses.

* `secret_id_ttl` - (Optional) The number of seconds after which any SecretID
  expires.

* `token_num_uses` - (Optional) The number of times issued tokens can be used.
  A value of 0 means unlimited uses.

* `token_ttl` - (Optional) The TTL period of tokens issued using this role,
  provided as a number of seconds.

* `token_max_ttl` - (Optional) The maximum allowed lifetime of tokens issued
  using this role, provided as a number of seconds.

* `period` - (Optional) If set, indicates that the token generated using this
  role should never expire. The token should be renewed within the duration
  specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. The maximum allowed lifetime of token issued using this
  role. Specified as a number of seconds.

## Attributes Reference

No additional attributes are exported by this resource.
