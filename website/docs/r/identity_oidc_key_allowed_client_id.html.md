---
layout: "vault"
page_title: "Vault: vault_identity_oidc_key_allowed_client_id resource"
sidebar_current: "docs-vault-identity-oidc-key-allowed-client-id"
description: |-
  Allows an Identity OIDC Role to use an OIDC Named key.
---

# vault\_identity\_oidc\_key\_allowed\_client\_id

Allows an Identity OIDC Role to use an OIDC Named key to generate
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

* `key_name` - (Required; Forces new resource) Name of the OIDC Key allow the Client ID.

* `allowed_client_id` - (Required; Forces new resource) Client ID to allow usage with the OIDC named key
