---
layout: "vault"
page_title: "Vault: vault_identity_oidc_role resource"
sidebar_current: "docs-vault-identity-oidc-role"
description: |-
  Creates an Identity OIDC Role for Vault
---

# vault\_identity\_oidc\_role

Creates an Identity OIDC Role for Vault Identity secrets engine to issue
[identity tokens](https://www.vaultproject.io/docs/secrets/identity/index.html#identity-tokens).

The Identity secrets engine is the identity management solution for Vault. It internally maintains
the clients who are recognized by Vault.

## Example Usage

```hcl
resource "vault_identity_oidc_key" "key" {
  name = "key"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role" {
  name = "role"
  key = vault_identity_oidc_key.key.name
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required; Forces new resource) Name of the OIDC Key to create.

* `rotation_period` - (Optional) How often to generate a new signing key in number of seconds

* `template` - (Optional) The template string to use for generating tokens. This may be in
  string-ified JSON or base64 format. See the
  [documentation](https://www.vaultproject.io/docs/secrets/identity/index.html#token-contents-and-templates)
  for the template format.

* `ttl` - (Optional) TTL of the tokens generated against the role in number of seconds.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the created role.

* `client_id` - The value that will be included in the `aud` field of all the OIDC identity
  tokens issued by this role

## Import

The key can be imported with the role name, for example:

```
$ terraform import vault_identity_oidc_role.role role
```
