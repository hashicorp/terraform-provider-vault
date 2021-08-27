---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-ldap-auth-backend"
description: |-
  Managing LDAP auth backends in Vault
---

# vault\_ldap\_auth\_backend

Provides a resource for managing an [LDAP auth backend within Vault](https://www.vaultproject.io/docs/auth/ldap.html).

## Example Usage

```hcl
resource "vault_ldap_auth_backend" "ldap" {
    path        = "ldap"
    url         = "ldaps://dc-01.example.org"
    userdn      = "OU=Users,OU=Accounts,DC=example,DC=org"
    userattr    = "sAMAccountName"
    upndomain   = "EXAMPLE.ORG"
    discoverdn  = false
    groupdn     = "OU=Groups,DC=example,DC=org"
    groupfilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
}
```

## Argument Reference

The following arguments are supported:

* `url` - (Required) The URL of the LDAP server

* `starttls` - (Optional) Control use of TLS when conecting to LDAP

* `tls_min_version` - (Optional) Minimum acceptable version of TLS

* `tls_max_version` - (Optional) Maximum acceptable version of TLS

* `insecure_tls` - (Optional) Control whether or TLS certificates must be validated

* `certificate` - (Optional) Trusted CA to validate TLS certificate

* `binddn` - (Optional) DN of object to bind when performing user search

* `bindpass` - (Optional) Password to use with `binddn` when performing user search

* `userdn` - (Optional) Base DN under which to perform user search

* `userattr` - (Optional) Attribute on user object matching username passed in

* `upndomain` - (Optional) The userPrincipalDomain used to construct UPN string

* `discoverdn`: (Optional) Use anonymous bind to discover the bind DN of a user.

* `deny_null_bind`: (Optional) Prevents users from bypassing authentication when providing an empty password.

* `upndomain`: (Optional) The `userPrincipalDomain` used to construct the UPN string for the authenticating user.

* `groupfilter` - (Optional) Go template used to construct group membership query

* `groupdn` - (Optional) Base DN under which to perform group search

* `groupattr` - (Optional) LDAP attribute to follow on objects returned by groupfilter

* `use_token_groups` - (Optional) Use the Active Directory tokenGroups constructed attribute of the user to find the group memberships

* `path` - (Optional) Path to mount the LDAP auth backend under

* `description` - (Optional) Description for the LDAP auth backend mount

* `local` - (Optional) Specifies if the auth method is local only.

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

* `token_num_uses` - (Optional) The number of times issued tokens can be used.
  A value of 0 means unlimited uses.

* `token_num_uses` - (Optional) The
  [period](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls),
  if any, in number of seconds to set on the token.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

For more details on the usage of each argument consult the [Vault LDAP API documentation](https://www.vaultproject.io/api-docs/auth/ldap).

~> **Important** Because Vault does not support reading the configured
credentials back from the API, Terraform cannot detect and correct drift
on `bindpass`. Changing the values, however, _will_ overwrite the
previously stored values.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `accessor` - The accessor for this auth mount.

## Import

LDAP authentication backends can be imported using the `path`, e.g.

```
$ terraform import vault_ldap_auth_backend.ldap ldap
```
