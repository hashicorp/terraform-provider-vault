---
layout: "vault"
page_title: "Vault: <TODO>"
sidebar_current: "<TODO>"
description: |-
  <TODO>
---

# <TODO>

<TODO>

## Example Usage

<TODO - this and HCL example below>
```hcl
resource "vault_jwt_auth_backend" "example" {
    description  = "Demonstration of the Terraform JWT auth backend"
    path = "jwt"
    oidc_discovery_url = "https://myco.auth0.com/"
    bound_issuer = "https://myco.auth0.com/"
}
```

## Argument Reference

The following arguments are supported:
* `path` - (Required) Path to where the back-end is mounted within Vault.
* `bound_issuer` - (Optional) The value against which to match the 'iss' claim in a JWT. Optional.
* `default_role` - (Optional) The default role to use if none is provided during login. If not set, a role is required during login.
* `jwks_ca_pem` - (Optional) The CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.
* `jwks_url` - (Optional) JWKS URL to use to authenticate signatures. Cannot be used with "oidc_discovery_url" or "jwt_validation_pubkeys".
* `jwt_supported_algs` - (Optional) A list of supported signing algorithms. Defaults to RS256.
* `jwt_validation_pubkeys` - (Optional) A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used with "jwks_url" or "oidc_discovery_url".
* `oidc_client_id` - (Optional) The OAuth Client ID configured with your OIDC provider.
* `oidc_client_secret` - (Optional) The OAuth Client Secret configured with your OIDC provider.
* `oidc_discovery_ca_pem` - (Optional) The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used.
* `oidc_discovery_url` - (Optional) OIDC Discovery URL, without any .well-known component (base path). Cannot be used with "jwks_url" or "jwt_validation_pubkeys".
* `oidc_response_mode` - (Optional) The response mode to be used in the OAuth2 request. Allowed values are 'query' and 'form_post'.
* `oidc_response_types` - (Optional) The response types to request. Allowed values are 'code' and 'id_token'. Defaults to 'code'.
