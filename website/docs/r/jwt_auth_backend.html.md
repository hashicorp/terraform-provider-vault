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

* `path` - (Required) Path to mount the JWT auth backend

* `description` - (Optional) The description of the auth backend

* `oidc_discovery_url` - (Optional) The OIDC Discovery URL, without any .well-known component (base path). Cannot be used in combination with `jwt_validation_pubkeys`

* `bound_issuer` - (Optional) The value against which to match the iss claim in a JWT

* `oidc_discovery_ca_pem` - (Optional) The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used

* `jwt_validation_pubkeys` - (Optional) A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used in combination with `oidc_discovery_url`

## Attributes Reference

No additional attributes are exposed by this resource.
