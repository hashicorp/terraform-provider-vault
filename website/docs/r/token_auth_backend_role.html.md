---
layout: "vault"
page_title: "Vault: vault_token_auth_backend_role resource"
sidebar_current: "docs-vault-resource-token-auth-backend-role"
description: |-
  Manages Token auth backend roles in Vault.
---

# vault\_token\_auth\_backend\_role

Manages Token auth backend role in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/token.html) for more
information.

## Example Usage

```hcl
resource "vault_token_auth_backend_role" "example" {
  role_name           = "my-role"
  allowed_policies    = ["dev", "test"]
  disallowed_policies = ["default"]
  orphan              = true
  period              = "86400"
  renewable           = true
  explicit_max_ttl    = "115200"
  path_suffix         = "path-suffix"
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role.

* `allowed_policies` (Optional) List of allowed policies for given role.

* `disallowed_policies` (Optional) List of disallowed policies for given role.

* `orphan` (Optional) If true, tokens created against this policy will be orphan tokens.

* `period` (Optional) The duration in which a token should be renewed. At each renewal, the token's TTL will be set to the value of this parameter.

* `renewable` (Optional) Wether to disable the ability of the token to be renewed past its initial TTL.

* `explicit_max_ttl` (Optional) If set, the token will have an explicit max TTL set upon it.

* `path_suffix` (Optional) Tokens created against this role will have the given suffix as part of their path in addition to the role name.

* `bound_cidrs` (Optional) If set, restricts usage of the generated token to client IPs falling within the range of the specified CIDR(s).

* `token_type` (Optional) Specifies the type of tokens that should be returned by the role. If either service or batch is specified, that kind of token will always be returned.

-> Due to a [bug](https://github.com/hashicorp/vault/issues/6296) with Vault, updating `path_suffix` or `bound_cidrs` to an empty string or list respectively will not actually update the value in Vault. Upgrade to Vault 1.1 and above to fix this, or [`taint`](https://www.terraform.io/docs/commands/taint.html) the resource. This *will* cause all existing tokens issued by this role to be revoked.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Token auth backend roles can be imported with `auth/token/roles/` followed by the `role_name`, e.g.

```
$ terraform import vault_token_auth_backend_role.example auth/token/roles/my-role
```
