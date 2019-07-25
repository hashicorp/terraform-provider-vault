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

The Identity secrets engine is the identity management solution for Vault. It internally
maintains the clients who are recognized by Vault.

Use this with [`vault_identity_oidc_key`](identity_oidc_key.html)
and [`vault_identity_oidc_key_allowed_client_id`](identity_oidc_key_allowed_client_id.html)
to configure a Role to generate Identity Tokens.

~> **NOTE on `allowed_client_ids`:** Terraform currently
provides both a standalone [Allowed Client ID](identity_oidc_key_allowed_client_id.html) (a single
Client ID), and a [OIDC Named Key](identity_oidc_key.html) with a inline list of Allowed Client IDs.
At this time you cannot use an OIDC Named Key inline list of Allowed Client IDs
in conjunction with any Allowed Client ID resources. Doing so will cause
a conflict of the list of Allowed Client IDs for the named Key.

## Example Usage

```hcl
resource "vault_identity_oidc_key" "key" {
  name      = "key"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role" {
  name = "role"
  key  = vault_identity_oidc_key.key.name
}

resource "vault_identity_oidc_key_allowed_client_id" "role" {
  key_name          = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.role.client_id
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required; Forces new resource) Name of the OIDC Key to create.

* `rotation_period` - (Optional) How often to generate a new signing key in number of seconds

* `verification_ttl` - (Optional) "Controls how long the public portion of a signing key will be
  available for verification after being rotated in seconds.

* `algorithm` - (Optional) Signing algorithm to use. Signing algorithm to use.
  Allowed values are: RS256 (default), RS384, RS512, ES256, ES384, ES512, EdDSA.

* `allowed_client_ids`: Array of role client ID allowed to use this key for signing. If
  empty, no roles are allowed. If `["*"]`, all roles are allowed.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the created key.

## Import

The key can be imported with the key name, for example:

```
$ terraform import vault_identity_oidc_key.key key
```
