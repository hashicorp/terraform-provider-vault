---
layout: "vault"
page_title: "Vault: vault_kubernetes_auth_backend_role data source"
sidebar_current: "docs-vault-datasource-kubernetes-auth-backend-role"
description: |-
  Reads Kubernetes auth backend roles in Vault.
---

# vault\_kubernetes\_auth\_backend\_role

Reads the Role of an Kubernetes from a Vault server. See the [Vault
documentation](https://www.vaultproject.io/api-docs/auth/kubernetes#read-role) for more
information.

## Example Usage

```hcl
data "vault_kubernetes_auth_backend_role" "role" {
  backend   = "my-kubernetes-backend"
  role_name = "my-role"
}

output "policies" {
  value = data.vault_kubernetes_auth_backend_role.role.policies
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role to retrieve the Role attributes for.

* `backend` - (Optional) The unique name for the Kubernetes backend the role to
  retrieve Role attributes for resides in. Defaults to "kubernetes".

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `bound_cirs` (Deprecated; use `token_bound_cidrs` instead if you are running Vault >= 1.2) - List of CIDR blocks. If set,
  specifies the blocks of IP addresses which can perform the login operation.

* `bound_service_account_names` - List of service account names able to access this role. If set to "*" all names are allowed, both this and bound_service_account_namespaces can not be "*".

* `bound_service_account_namespaces` - List of namespaces allowed to access this role. If set to "*" all namespaces are allowed, both this and bound_service_account_names can not be set to "*".

* `ttl` (Deprecated; use `token_ttl` instead if you are running Vault >= 1.2) - The TTL period of tokens issued using this
  role in seconds.

* `max_ttl` (Deprecated; use `token_max_ttl` instead if you are running Vault >= 1.2) - The maximum allowed lifetime of
  tokens issued in seconds using this role.

* `num_uses` (Deprecated; use `token_num_uses` instead if you are running Vault >= 1.2) - Number of times issued tokens can
  be used. Setting this to 0 or leaving it unset means unlimited uses.

* `period` (Deprecated; use `token_period` instead if you are running Vault >= 1.2) - If set, indicates that the token
  generated using this role should never expire. The token should be renewed within the
  duration specified by this value. At each renewal, the token's TTL will be set to the value
  of this parameter.

* `policies` (Deprecated; use `token_policies` instead if you are running Vault >= 1.2) - Policies to be set on tokens issued
  using this role.
  
* `audience` - (Optional) Audience claim to verify in the JWT.

### Common Token Attributes

These attributes are common across several Authentication Token resources since Vault 1.2.

* `token_ttl` - The incremental lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_max_ttl` - The maximum lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_period` - (Optional) If set, indicates that the
  token generated using this role should never expire. The token should be renewed within the
  duration specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. Specified in seconds.

* `token_policies` - List of policies to encode onto generated tokens. Depending
  on the auth method, this list may be supplemented by user/group/other values.

* `token_bound_cidrs` - List of CIDR blocks; if set, specifies blocks of IP
  addresses which can authenticate successfully, and ties the resulting token to these blocks
  as well.

* `token_explicit_max_ttl` - If set, will encode an
  [explicit max TTL](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token in number of seconds. This is a hard cap even if `token_ttl` and
  `token_max_ttl` would otherwise allow a renewal.

* `token_no_default_policy` - If set, the default policy will not be set on
  generated tokens; otherwise it will be added to the policies set in token_policies.

* `token_num_uses` - The
  [period](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls),
  if any, in number of seconds to set on the token.

* `token_type` - The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.
