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

Manage OIDC auth backend with write-only secret (recommended):

```hcl
resource "vault_jwt_auth_backend" "example" {
    description                     = "Demonstration of the Terraform JWT auth backend"
    path                            = "oidc"
    type                            = "oidc"
    oidc_discovery_url              = "https://myco.auth0.com/"
    oidc_client_id                  = "1234567890"
    oidc_client_secret_wo           = "secret123456"
    oidc_client_secret_wo_version   = 1  # Increment to update the secret
    bound_issuer                    = "https://myco.auth0.com/"
    tune {
        listing_visibility = "unauth"
    }
}
```

Configuring the auth backend with a `provider_config:

```hcl
resource "vault_jwt_auth_backend" "gsuite" {
    description = "OIDC backend"
    oidc_discovery_url = "https://accounts.google.com"
    path = "oidc"
    type = "oidc"
    provider_config = {
        provider = "gsuite"
        fetch_groups = true
        fetch_user_info = true
        groups_recurse_max_depth = 1
    }
}
```


## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) Path to mount the JWT/OIDC auth backend

* `disable_remount` - (Optional) If set, opts out of mount migration on path updates.
  See here for more info on [Mount Migration](https://www.vaultproject.io/docs/concepts/mount-migration)

* `type` - (Optional) Type of auth backend. Should be one of `jwt` or `oidc`. Default - `jwt`

* `description` - (Optional) The description of the auth backend

* `oidc_discovery_url` - (Optional) The OIDC Discovery URL, without any .well-known component (base path). Cannot be used in combination with `jwt_validation_pubkeys`

* `oidc_discovery_ca_pem` - (Optional) The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used

* `oidc_client_id` - (Optional) Client ID used for OIDC backends

* `oidc_client_secret` - (Optional) Client Secret used for OIDC backends. **Note:** This field is stored in state. For enhanced security, use `oidc_client_secret_wo` instead.

* `oidc_client_secret_wo_version` - (Optional) Version counter for the write-only `oidc_client_secret_wo` field. Increment this value to trigger an update of the client secret in Vault. Required when using `oidc_client_secret_wo`.

* `oidc_response_mode` - (Optional) The response mode to be used in the OAuth2 request. Allowed values are `query` and `form_post`. Defaults to `query`. If using Vault namespaces, and `oidc_response_mode` is `form_post`, then `namespace_in_state` should be set to `false`.

* `oidc_response_types` - (Optional) List of response types to request. Allowed values are 'code' and 'id_token'. Defaults to `["code"]`. Note: `id_token` may only be used if `oidc_response_mode` is set to `form_post`.

* `jwks_url` - (Optional) JWKS URL to use to authenticate signatures. Cannot be used with "oidc_discovery_url" or "jwt_validation_pubkeys".

* `jwks_ca_pem` - (Optional) The CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.

* `jwks_pairs` - (Optional) List of JWKS URL and optional CA certificate pairs. Cannot be used with `jwks_url` or `jwks_ca_pem`. Requires Vault 1.16+.

* `jwt_validation_pubkeys` - (Optional) A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used in combination with `oidc_discovery_url`

* `bound_issuer` - (Optional) The value against which to match the iss claim in a JWT

* `jwt_supported_algs` - (Optional) A list of supported signing algorithms. Vault 1.1.0 defaults to [RS256] but future or past versions of Vault may differ

* `default_role` - (Optional) The default role to use if none is provided during login

* `provider_config` - (Optional) Provider specific handling configuration. All values may be strings, and the provider will convert to the appropriate type when configuring Vault.

* `local` - (Optional) Specifies if the auth method is local only.

* `namespace_in_state` - (Optional) Pass namespace in the OIDC state parameter instead of as a separate query parameter. With this setting, the allowed redirect URL(s) in Vault and on the provider side should not contain a namespace query parameter. This means only one redirect URL entry needs to be maintained on the OIDC provider side for all vault namespaces that will be authenticating against it. Defaults to true for new configs

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

## Ephemeral Attributes Reference

The following write-only attributes are supported:

* `oidc_client_secret_wo` - (Optional) Write-only Client Secret used for OIDC backends. This value will **never** be stored in Terraform state. Mutually exclusive with `oidc_client_secret`. Must be used with `oidc_client_secret_wo_version`. To rotate the secret, update the value and increment `oidc_client_secret_wo_version`.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `accessor` - The accessor for this auth method

## Import

JWT auth backend can be imported using the `path`, e.g.

```
$ terraform import vault_jwt_auth_backend.oidc oidc
```

or

```
$ terraform import vault_jwt_auth_backend.jwt jwt
```
