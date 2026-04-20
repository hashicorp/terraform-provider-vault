---
layout: "vault"
page_title: "Vault: vault_cert_auth_backend_role resource"
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

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Optional string: "cert") Path to the mounted Cert auth backend

* `name` - (Required string) Name of the role

* `certificate` - (Required string) CA certificate used to validate client certificates

* `allowed_names` - (Optional string) DEPRECATED: Please use the individual `allowed_X_sans` parameters instead. Allowed subject names for authenticated client certificates

* `allowed_common_names` - (Optional array: []) Allowed the common names for authenticated client certificates

* `allowed_dns_sans` - (Optional array: []) Allowed alternative dns names for authenticated client certificates

* `allowed_email_sans` - (Optional array: []) Allowed emails for authenticated client certificates

* `allowed_uri_sans` - (Optional array: []) Allowed URIs for authenticated client certificates

* `allowed_organizational_units` - (Optional array: []) Allowed organization units for authenticated client certificates.

* `required_extensions` - (Optional array: []) TLS extensions required on
  client certificates

* `display_name` - (Optional string: "") The name to display on tokens issued under this role.

* `ocsp_enabled` (Optional bool: false) - If enabled, validate certificates'
  revocation status using OCSP. Requires Vault version 1.13+.

* `ocsp_ca_certificates` (Optional string: "") Any additional CA certificates
  needed to verify OCSP responses. Provided as base64 encoded PEM data.
  Requires Vault version 1.13+.

* `ocsp_servers_override` (Optional array: []): A comma-separated list of OCSP
  server addresses. If unset, the OCSP server is determined from the
  AuthorityInformationAccess extension on the certificate being inspected.
  Requires Vault version 1.13+.

* `ocsp_fail_open` (Optional bool: false) - If true and an OCSP response cannot
  be fetched or is of an unknown status, the login will proceed as if the
  certificate has not been revoked.
  Requires Vault version 1.13+.

* `ocsp_query_all_servers` (Optional bool: false) - If set to true, rather than
  accepting the first successful OCSP response, query all servers and consider
  the certificate valid only if all servers agree.
  Requires Vault version 1.13+.

* `ocsp_max_retries` (Optional int: 4) - The number of retries to attempt when
  connecting to an OCSP server. Defaults to 4 retries.
  Must be a non-negative value. Requires Vault version 1.16+.

* `ocsp_this_update_max_age` (Optional int: 0) - The maximum age in seconds of the
  'thisUpdate' field in an OCSP response before it is considered too old.
  Defaults to 0 (disabled). Must be a non-negative value.
  Requires Vault version 1.16+.

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

* `token_num_uses` - (Optional) The [maximum number](https://www.vaultproject.io/api-docs/auth/cert#token_num_uses)
   of times a generated token may be used (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

* `alias_metadata` - (Optional) The metadata to be tied to generated entity alias.
  This should be a list or map containing the metadata in key value pairs.

For more details on the usage of each argument consult the [Vault Cert API documentation](https://www.vaultproject.io/api-docs/auth/cert).

## Attribute Reference

No additional attributes are exposed by this resource.
