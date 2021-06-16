---
layout: "vault"
page_title: "Vault: vault_jwt_auth_backend resource"
sidebar_current: "docs-vault-resource-jwt-auth-backend"
description: |-
  Managing JWT/OIDC auth backends in Vault
---

# vault\_jwt\_auth\_backend

Provides a resource for managing an
[JWT auth backend within Vault](https://www.vaultproject.io/docs/auth/jwt.html).

## Example Usage

Manage JWT auth backend:

```hcl
resource "vault_jwt_auth_backend" "example" {
    description         = "Demonstration of the Terraform JWT auth backend"
    path                = "jwt"
    oidc_discovery_url  = "https://myco.auth0.com/"
    bound_issuer        = "https://myco.auth0.com/"
}
```

Manage OIDC auth backend:

```hcl
resource "vault_jwt_auth_backend" "example" {
    description         = "Demonstration of the Terraform JWT auth backend"
    path                = "oidc"
    type                = "oidc"
    oidc_discovery_url  = "https://myco.auth0.com/"
    oidc_client_id      = "1234567890"
    oidc_client_secret  = "secret123456"
    bound_issuer        = "https://myco.auth0.com/"
    tune {
        listing_visibility = "unauth"
    }
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) Path to mount the JWT/OIDC auth backend

* `type` - (Optional) Type of auth backend. Should be one of `jwt` or `oidc`. Default - `jwt`

* `description` - (Optional) The description of the auth backend

* `oidc_discovery_url` - (Optional) The OIDC Discovery URL, without any .well-known component (base path). Cannot be used in combination with `jwt_validation_pubkeys`

* `oidc_discovery_ca_pem` - (Optional) The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used

* `oidc_client_id` - (Optional) Client ID used for OIDC backends

* `oidc_client_secret` - (Optional) Client Secret used for OIDC backends

* `jwks_url` - (Optional) JWKS URL to use to authenticate signatures. Cannot be used with "oidc_discovery_url" or "jwt_validation_pubkeys".

* `jwks_ca_pem` - (Optional) The CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.

* `jwt_validation_pubkeys` - (Optional) A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used in combination with `oidc_discovery_url`

* `bound_issuer` - (Optional) The value against which to match the iss claim in a JWT

* `jwt_supported_algs` - (Optional) A list of supported signing algorithms. Vault 1.1.0 defaults to [RS256] but future or past versions of Vault may differ

* `default_role` - (Optional) The default role to use if none is provided during login

* `provider_config` - (Optional) Provider specific handling configuration

* tune - (Optional) Extra configuration block. Structure is documented below.

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

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `accessor` - The accessor for this auth method

## Import

JWT auth backend can be imported using the `type`, e.g.

```
$ terraform import vault_jwt_auth_backend.oidc oidc
```

or

```
$ terraform import vault_jwt_auth_backend.jwt jwt
```
