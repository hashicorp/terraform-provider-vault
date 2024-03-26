---
layout: "vault"
page_title: "Vault: vault_saml_auth_backend_role resource"
sidebar_current: "docs-vault-resource-saml-auth-backend-role"
description: |-
Manages SAML auth backend roles in Vault.
---

# vault\_saml\_auth\_backend\_role

Manages an SAML auth backend role in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/saml.html) for more
information.

## Example Usage

```hcl
resource "vault_saml_auth_backend" "example" {
  path             = "saml"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback"]
  default_role     = "default-role"
}

resource "vault_saml_auth_backend_role" "example" {
  path                = vault_saml_auth_backend.example.path
  name                = "my-role"
  groups_attribute    = "groups"
  bound_attributes    = {
    group = "admin"
  }
  bound_subjects      = ["*example.com"]
  token_policies      = ["writer"]
  token_ttl           = 86400
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Required) Path where the auth backend is mounted.

* `name` - (Required) Unique name of the role.

* `bound_subjects` - (Optional) List of subjects being asserted for SAML authentication.

* `bound_attributes` - (Optional) Mapping of attribute names to values that are expected to
  exist in the SAML assertion.

* `bound_subjects_type` - (Optional) The type of matching assertion to perform on `bound_subjects`.

* `bound_attributes_type` - (Optional) The type of matching assertion to perform on
  `bound_attributes_type`.

* `groups_attribute` - (Optional) The attribute to use to identify the set of groups to which the
  user belongs.


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

* `token_num_uses` - (Optional) The [maximum number](https://developer.hashicorp.com/vault/api-docs/auth/saml#token_num_uses)
  of times a generated token may be used (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

SAML authentication backend roles can be imported using the `path`, e.g.

```
$ terraform import vault_saml_auth_backend_role.example auth/saml/role/my-role
```
