---
layout: "vault"
page_title: "Vault: vault_cf_auth_backend_role resource"
sidebar_current: "docs-vault-resource-cf-auth-backend-role"
description: |-
  Manages roles for the CloudFoundry auth backend in Vault.
---

# vault\_cf\_auth\_backend\_role

Manages a role for the [CloudFoundry (CF) auth method](https://developer.hashicorp.com/vault/docs/auth/cf) in Vault.
Roles define the constraints that must be satisfied by a CF instance certificate
at login time, and the token parameters issued on a successful login.

## Example Usage

```hcl
resource "vault_auth_backend" "cf" {
  type = "cf"
  path = "cf"
}

resource "vault_policy" "cf_policy" {
  name   = "cf-policy"
  policy = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_cf_auth_backend_role" "role" {
  mount               = vault_auth_backend.cf.path
  name                = "my-role"
  bound_space_ids         = ["space-uuid-1"]
  bound_organization_ids = ["org-uuid-1"]
  disable_ip_matching = true
  token_ttl           = 3600
  token_policies      = [vault_policy.cf_policy.name]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) The mount path for the CF auth engine in Vault.

* `name` - (Required) The name of the CF auth role.

* `bound_application_ids` - (Optional) An optional set of CF application IDs. If
  set, a logging-in instance must belong to one of these applications.

* `bound_space_ids` - (Optional) An optional set of CF space IDs. If set, a
  logging-in instance must belong to one of these spaces.

* `bound_organization_ids` - (Optional) An optional set of CF organization IDs.
  If set, a logging-in instance must belong to one of these organizations.

* `bound_instance_ids` - (Optional) An optional set of CF instance IDs. If set,
  the logging-in instance's ID must appear in this list.

* `disable_ip_matching` - (Optional) If `true`, disables the default behavior
  that requires login requests to originate from an IP address listed in the
  instance certificate. Useful when CF instances sit behind a load balancer or
  NAT. Defaults to `false`.

### Common Token Arguments

These arguments are common across several Authentication Token resources since Vault 1.2.

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in
  number of seconds. Its current value will be referenced at renewal time.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in
  number of seconds. Its current value will be referenced at renewal time.

* `token_period` - (Optional) If set, indicates that the token generated using
  this role should never expire. The token should be renewed within the duration
  specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. Specified in seconds.

* `token_policies` - (Optional) List of policies to encode onto generated tokens.
  Depending on the auth method, this list may be supplemented by user/group/other
  values.

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks
  of IP addresses which can authenticate successfully, and ties the resulting
  token to these blocks as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an
  [explicit max TTL](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token in number of seconds. This is a hard cap even if `token_ttl`
  and `token_max_ttl` would otherwise allow a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be
  set on generated tokens; otherwise it will be added to the policies set in
  `token_policies`.

* `token_num_uses` - (Optional) The maximum number of times a generated token may
  be used (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be
  `service`, `batch`, or `default` to use the mount's tuned default (which unless
  changed will be `service` tokens).

* `alias_metadata` - (Optional) A map of metadata key/value pairs to attach to
  the token alias. Requires Vault 1.21+. On older Vault versions the CF auth
  plugin does not support this field and will silently ignore it.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

CF auth backend roles can be imported using `auth/`, the `mount` path, `/roles/`,
and the role `name`, e.g.

```
$ terraform import vault_cf_auth_backend_role.role auth/cf/roles/my-role
```

The namespace can be set using the environment variable `TERRAFORM_VAULT_NAMESPACE`.
