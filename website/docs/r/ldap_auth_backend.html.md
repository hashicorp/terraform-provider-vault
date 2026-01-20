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
    path              = "ldap"
    url               = "ldaps://dc-01.example.org"
    userdn            = "OU=Users,OU=Accounts,DC=example,DC=org"
    userattr          = "sAMAccountName"
    upndomain         = "EXAMPLE.ORG"
    discoverdn        = false
    groupdn           = "OU=Groups,DC=example,DC=org"
    groupfilter       = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
    rotation_schedule = "0 * * * SAT"
    rotation_window   = 3600
    request_timeout               = 30
    dereference_aliases           = "always"
    enable_samaccountname_login   = false
    anonymous_group_search        = false
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `url` - (Required) The URL of the LDAP server

* `starttls` - (Optional) Control use of TLS when conecting to LDAP

* `case_sensitive_names` - (Optional) Control case senstivity of objects fetched from LDAP, this is used for object matching in vault

* `max_page_size` - (Optional) Sets the max page size for LDAP lookups, by default it's set to -1.
   *Available only for Vault 1.11.11+, 1.12.7+, and 1.13.3+*.

* `tls_min_version` - (Optional) Minimum acceptable version of TLS

* `tls_max_version` - (Optional) Maximum acceptable version of TLS

* `insecure_tls` - (Optional) Control whether or TLS certificates must be validated

* `certificate` - (Optional) Trusted CA to validate TLS certificate

* `binddn` - (Optional) DN of object to bind when performing user search

* `bindpass` - (Optional) Password to use with `binddn` when performing user search. Conflicts with `bindpass_wo`.

* `bindpass_wo_version` - (Optional) Version counter for write-only bind password.
  Required when using `bindpass_wo`. For more information about write-only attributes, see 
  [using write-only attributes](/docs/providers/vault/guides/using_write_only_attributes).

* `userdn` - (Optional) Base DN under which to perform user search

* `userattr` - (Optional) Attribute on user object matching username passed in

* `userfilter` - (Optional) LDAP user search filter

* `upndomain` - (Optional) The userPrincipalDomain used to construct UPN string

* `discoverdn`: (Optional) Use anonymous bind to discover the bind DN of a user.

* `deny_null_bind`: (Optional) Prevents users from bypassing authentication when providing an empty password.

* `upndomain`: (Optional) The `userPrincipalDomain` used to construct the UPN string for the authenticating user.

* `groupfilter` - (Optional) Go template used to construct group membership query

* `groupdn` - (Optional) Base DN under which to perform group search

* `groupattr` - (Optional) LDAP attribute to follow on objects returned by groupfilter

* `username_as_alias` - (Optional) Force the auth method to use the username passed by the user as the alias name.

* `use_token_groups` - (Optional) Use the Active Directory tokenGroups constructed attribute of the user to find the group memberships

* `path` - (Optional) Path to mount the LDAP auth backend under

* `disable_remount` - (Optional) If set, opts out of mount migration on path updates.
  See here for more info on [Mount Migration](https://www.vaultproject.io/docs/concepts/mount-migration)

* `description` - (Optional) Description for the LDAP auth backend mount

* `local` - (Optional) Specifies if the auth method is local only.

* `connection_timeout` - (Optional) Timeout in seconds when connecting to LDAP before attempting to connect to the next server in the URL provided in `url` (integer: 30)

* `rotation_period` - (Optional) The amount of time in seconds Vault should wait before rotating the root credential.
  A zero value tells Vault not to rotate the root credential. The minimum rotation period is 10 seconds. Requires Vault Enterprise 1.19+.

* `rotation_schedule` - (Optional) The schedule, in [cron-style time format](https://en.wikipedia.org/wiki/Cron),
  defining the schedule on which Vault should rotate the root token. Requires Vault Enterprise 1.19+.

* `rotation_window` - (Optional) The maximum amount of time in seconds allowed to complete
  a rotation when a scheduled token rotation occurs. The default rotation window is
  unbound and the minimum allowable window is `3600`. Requires Vault Enterprise 1.19+.

* `disable_automated_rotation` - (Optional) Cancels all upcoming rotations of the root credential until unset. Requires Vault Enterprise 1.19+.

* `tune` - (Optional) Extra configuration block. Structure is documented below.

The `tune` block is used to tune the auth backend:

* `default_lease_ttl` - (Optional) Specifies the default time-to-live.
  If set, this overrides the global default.
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `max_lease_ttl` - (Optional) Specifies the maximum time-to-live.
  If set, this overrides the global default.
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `audit_non_hmac_response_keys` - (Optional) Specifies the list of keys that will
  not be HMAC'd by audit devices in the response data object.

* `audit_non_hmac_request_keys` - (Optional) Specifies the list of keys that will
  not be HMAC'd by audit devices in the request data object.

* `listing_visibility` - (Optional) Specifies whether to show this mount in
  the UI-specific listing endpoint. Valid values are "unauth" or "hidden".

* `passthrough_request_headers` - (Optional) List of headers to whitelist and
  pass from the request to the backend.

* `allowed_response_headers` - (Optional) List of headers to whitelist and allowing
  a plugin to include them in the response.

* `token_type` - (Optional) Specifies the type of tokens that should be returned by
  the mount. Valid values are "default-service", "default-batch", "service", "batch".

### Common Token Arguments

These arguments are common across several Authentication Token resources since Vault 1.2.

* `request_timeout` - (Optional) Timeout, in seconds, for the connection when making requests against the server before returning back an error.

* `dereference_aliases` - (Optional) When aliases should be dereferenced on search operations. Accepted values are 'never', 'finding', 'searching', 'always'. Defaults to 'never'.

* `enable_samaccountname_login` - (Optional) Lets Active Directory LDAP users log in using sAMAccountName or userPrincipalName when the upndomain parameter is set. Requires Vault 1.19.0+.

* `anonymous_group_search` - (Optional) Use anonymous binds when performing LDAP group searches (note: even when true, the initial credentials will still be used for the initial connection test).

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

* `token_num_uses` - (Optional) The [maximum number](https://www.vaultproject.io/api-docs/ldap#token_num_uses)
   of times a generated token may be used (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

* `alias_metadata` - (Optional) The metadata to be tied to generated entity alias.
  This should be a list or map containing the metadata in key value pairs.

For more details on the usage of each argument consult the [Vault LDAP API documentation](https://www.vaultproject.io/api-docs/auth/ldap).

~> **Important** Because Vault does not support reading the configured
credentials back from the API, Terraform cannot detect and correct drift
on `bindpass`. Changing the values, however, _will_ overwrite the
previously stored values.

## Ephemeral Attributes Reference

The following write-only attributes are supported:

* `bindpass_wo` - (Optional) Write-only bind password to use for LDAP authentication. Can be updated. Conflicts with `bindpass`.
  **Note**: This property is write-only and will not be read from the API.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `accessor` - The accessor for this auth mount.

## Import

LDAP authentication backends can be imported using the `path`, e.g.

```
$ terraform import vault_ldap_auth_backend.ldap ldap
```
