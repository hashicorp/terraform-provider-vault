---
layout: "vault"
page_title: "Vault: vault_oci_auth_backend_role resource"
sidebar_current: "docs-vault-resource-oci-auth-backend-role"
description: |-
  Manages OCI (Oracle Cloud Infrastructure) auth backend roles in Vault.
---

# vault\_oci\_auth\_backend\_role

Manages an OCI (Oracle Cloud Infrastructure) auth backend role in a 
Vault server. Roles constrain the instances or principals that can
perform the login operation against the backend. See the [Vault
documentation](https://developer.hashicorp.com/vault/docs/auth/oci) for
more information.

## Example Usage

```hcl
resource "vault_oci_auth_backend" "oci" {
  path            = "oci"
  home_tenancy_id = "ocid1.tenancy.oc1..aaaaaaaah7zkvaffv26pzyauoe2zbnionqvhvsexamplee557wakiofi4ysgqq"
}

resource "vault_oci_auth_backend_role" "example" {
  backend        = vault_oci_auth_backend.oci.path
  name           = "test-role"
  ocid_list      = ["ocid1.group.oc1..aaaaaaaabmyiinfq32y5aha3r2yo4exampleo4yg3fjk2sbne4567tropaa", "ocid1.dynamicgroup.oc1..aaaaaaaabvfwct33xri5examplegov4zyjp3rd5d7sk9jjdggxijhco56hrq"]
  token_ttl      = 60
  token_max_ttl  = 120
  token_policies = ["default", "dev", "prod"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required) The name of the role.

* `ocid_list` - (Required) The list of Group or Dynamic Group OCIDs that can take this role.

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

* `token_num_uses` - (Optional) The [maximum number](https://developer.hashicorp.com/vault/api-docs/auth/oci#token_num_uses)
   of times a generated token may be used (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

OCI auth backend roles can be imported using `auth/`, the `backend` path, `/role/`, and the `role` name e.g.

```
$ terraform import vault_oci_auth_backend_role.example auth/oci/role/test-role
```
