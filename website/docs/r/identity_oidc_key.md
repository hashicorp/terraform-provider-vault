---
layout: "vault"
page_title: "Vault: vault_identity_oidc_key resource"
sidebar_current: "docs-vault-identity-oidc-key"
description: |-
  Creates an Identity OIDC Named Key for Vault
---

# vault\_identity\_oidc\_key

Creates an Identity OIDC Named Key for Vault Identity secrets engine which is used by a role
to sign
[identity tokens](https://www.vaultproject.io/docs/secrets/identity/index.html#identity-tokens).

The Identity secrets engine is the identity management solution for Vault. It internally maintains
the clients who are recognized by Vault.

## Example Usage

```hcl
resource "vault_identity_oidc_key" "key" {
  name = "key"
  algorithm = "RS256"
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the OIDC Key to create.

* `rotation_period` - (Optional) How often to generate a new signing key in number of seconds

* `verification_ttl` - (Optional) "Controls how long the public portion of a signing key will be
  available for verification after being rotated in seconds.

* `algorithm` - (Optional) Signing algorithm to use. This will default to "RS256", and is currently
  the only allowed value.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the created key.

## Import

The key can be imported with the key name, for example:

```
$ terraform import vault_identity_oidc_key.key key
```
