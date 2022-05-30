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

You need to create a role with a [named key](identity_oidc_key.html).
At creation time, the key can be created independently of the role. However, the key must
exist before the role can be used to issue tokens. You must also configure the key with the
role's Client ID to allow the role to use the key.

```hcl
variable "key" {
  description = "Name of the OIDC Key"
  default     = "key"
}

resource "vault_identity_oidc_key" "key" {
  name      = var.key
  algorithm = "RS256"

  allowed_client_ids = [
    vault_identity_oidc_role.role.client_id
  ]
}

resource "vault_identity_oidc_role" "role" {
  name = "role"
  key  = var.key
}
```

If you want to create the key first before creating the role, you can use a separate
[resource](identity_oidc_key_allowed_client_id.html) to configure the allowed Client ID on
the key.

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

* `name` - (Required; Forces new resource) Name of the OIDC Role to create.

* `key` - (Required; Forces new resource) A configured named key, the key must already exist
  before tokens can be issued.

* `template` - (Optional) The template string to use for generating tokens. This may be in
  string-ified JSON or base64 format. See the
  [documentation](https://www.vaultproject.io/docs/secrets/identity/index.html#token-contents-and-templates)
  for the template format.

* `ttl` - (Optional) TTL of the tokens generated against the role in number of seconds.

* `client_id` - (Optional) The value that will be included in the `aud` field of all the OIDC identity
  tokens issued by this role

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the created role.

## Import

The key can be imported with the role name, for example:

```
$ terraform import vault_identity_oidc_role.role role
```
