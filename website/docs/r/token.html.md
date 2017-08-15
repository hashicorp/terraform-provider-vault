---
layout: "vault"
page_title: "Vault: vault_token resource"
sidebar_current: "docs-vault-resource-token"
description: |-
  Creates Vault tokens
---

# vault\_token

Creates Vault tokens that can be used to help bootstrapping instances

~> **Important** If tokens are created without wrap set to true, the
token will be visible in plain text in the state files, it would be
recommended to only use wrapped tokens.

## Example Usage

```hcl
resource "vault_token" "example" {
  display_name = "example name"
  policies = ["example-policy"]
}
```

## Argument Reference

The following arguments are supported:
* `display_name` -  (Optional) String. Display name to associate
with the token

* `policies` - (Optional) A list of strings containing policies to
apply to token. This defaults to the default policy if not set.

* `meta` - (Optional) A map of string to string valued metadata. This
is passed to the audit backends.

* `role` - (Optional) String. Role to apply to token.

* `ttl` - (Optional) String. TTL of Vault token in seconds unless
appended with (s, m, h) If not set this will default to 30 days.

* `explicit_max_ttl` - (Optional) String. Maximum TTL of Vault token.
in seconds unless appended with (s, m, h) If not set this will default
to 30 days.

* `orphan` - (Optional) True/False. Make an orphan Vault token.
Defaults to true.

* `renewable` - (Optional) True/False. Make token renewable.
Defaults to true.

* `period` - (Optional) String. In seconds unless appended with (s, m, h).
If set will create a periodic token with the specified period.

* `wrap` - (Optional) True/False. Create wrapped Vault token.
Defaults to true.

* `wrap_ttl` - (Optional) String TTL for wrapped token in seconds,
unless appended with (s, m, h). Defaults to 1 hour.

* `no_default_policy` - (Optional) True/False. Do not include
default policy. Defaults to False.

## Required Vault Capabilities

Use of this resource requires the `update` and `sudo` capabilities
on the path `auth/token`.

If the token accessor comes back with `bad token`, the token has
likely been revoked. Therefore it will be removedfrom the state file
and will be recreated on the following run.

## Attributes Reference

* `token` - Vault token that has been created, if wrapped, this will
be the wrapping token.

* `accessor` - Returned Vault token accessor. If wrapped, this will
be the accessor of the wrapped token.
