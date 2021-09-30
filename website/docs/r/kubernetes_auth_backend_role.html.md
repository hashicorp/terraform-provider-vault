---
layout: "vault"
page_title: "Vault: vault_kubernetes_auth_backend_role resource"
sidebar_current: "docs-vault-resource-kubernetes-auth-backend-role"
description: |-
  Manages Kubernetes auth backend roles in Vault.
---

# vault\_kubernetes\_auth\_backend\_role

Manages an Kubernetes auth backend role in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/kubernetes.html) for more
information.

## Example Usage

```hcl
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_role" "example" {
  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = "example-role"
  bound_service_account_names      = ["example"]
  bound_service_account_namespaces = ["example"]
  token_ttl                        = 3600
  token_policies                   = ["default", "dev", "prod"]
  audience                         = "vault"
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) Name of the role.

* `bound_service_account_names` - (Required) List of service account names able to access this role. If set to `["*"]` all names are allowed, both this and bound_service_account_namespaces can not be "*".

* `bound_service_account_namespaces` - (Required) List of namespaces allowed to access this role. If set to `["*"]` all namespaces are allowed, both this and bound_service_account_names can not be set to "*".

* `backend` - (Optional) Unique name of the kubernetes backend to configure.

* `audience` - (Optional) Audience claim to verify in the JWT.

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

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Kubernetes auth backend role can be imported using the `path`, e.g.

```
$ terraform import vault_kubernetes_auth_backend_role.foo auth/kubernetes/role/foo
```
