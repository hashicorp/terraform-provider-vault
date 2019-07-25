---
layout: "vault"
page_title: "Vault: vault_identity_oidc resource"
sidebar_current: "docs-vault-identity-oidc"
description: |-
  Configure the Identity Tokens Backend for Vault
---

# vault\_identity\_oidc

Configure the [Identity Tokens Backend](https://www.vaultproject.io/docs/secrets/identity/index.html#identity-tokens).

The Identity secrets engine is the identity management solution for Vault. It internally maintains
the clients who are recognized by Vault.

~> **NOTE:** Each Vault server may only have one Identity Tokens Backend configuration. Multiple configurations of the resource against the same Vault server will cause a perpetual difference.

## Example Usage

```hcl
resource "vault_identity_oidc" "server" {
  issuer = "https://www.acme.com"
}
```

## Argument Reference

The following arguments are supported:

* `issuer` - (Optional) Issuer URL to be used in the iss claim of the token. If not set, Vault's
  `api_addr` will be used. The issuer is a case sensitive URL using the https scheme that contains
  scheme, host, and optionally, port number and path components, but no query or fragment
  components.

## Attributes Reference

No additional attributes are exposed by this resource.
