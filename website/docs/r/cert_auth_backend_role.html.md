---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-cert-auth-backend-role"
description: |-
  Managing roles in an Cert auth backend in Vault
---

# vault\_cert\_auth\_backend\_role

Provides a resource to create a role in an [Cert auth backend within Vault](https://www.vaultproject.io/docs/auth/cert.html).

## Example Usage

```hcl
resource "vault_auth_backend" "cert" {
    path = "cert"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "cert" {
    name           = "foo"
    certificate    = file("/path/to/certs/ca-cert.pem")
    backend        = vault_auth_backend.cert.path
    allowed_names  = ["foo.example.org", "baz.example.org"]
    token_ttl      = 300
    token_max_ttl  = 600
    token_policies = ["foo"]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the role

* `certificate` - (Required) CA certificate used to validate client certificates

* `allowed_names` - (Optional) Allowed subject names for authenticated client certificates

* `allowed_common_names` - (Optional) Allowed the common names for authenticated client certificates

* `allowed_dns_sans` - (Optional) Allowed alternative dns names for authenticated client certificates

* `allowed_email_sans` - (Optional) Allowed emails for authenticated client certificates

* `allowed_uri_sans` - (Optional) Allowed URIs for authenticated client certificates

* `allowed_organization_units` - (Optional) Allowed organization units for authenticated client certificates

* `required_extensions` - (Optional) TLS extensions required on client certificates

* `display_name` - (Optional) The name to display on tokens issued under this role.

* `backend` - (Optional) Path to the mounted Cert auth backend

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

### Deprecated Arguments

These arguments are deprecated since Vault 1.2 in favour of the common token arguments
documented above.

* `bound_cidrs` - (Optional; Deprecated, use `token_bound_cidrs` instead if you are running Vault >= 1.2) Restriction usage of the
  certificates to client IPs falling within the range of the specified CIDRs

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

For more details on the usage of each argument consult the [Vault Cert API documentation](https://www.vaultproject.io/api/auth/cert/index.html).

## Attribute Reference

No additional attributes are exposed by this resource.
