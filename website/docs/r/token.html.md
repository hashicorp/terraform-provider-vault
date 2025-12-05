---
layout: "vault"
page_title: "Vault: vault_token resource"
sidebar_current: "docs-vault-resource-token"
description: |-
  Writes token for Vault
---

# vault\_token

Provides a resource to generate a vault token with its options. The token renewing is supported through optional
arguments.

The token used by Terraform will require update access to the `auth/token/lookup-accessor`
path to create tokens and the `auth/token/revoke-accessor` path in Vault to
destroy a token.

```hcl
path "auth/token/lookup-accessor" {
  capabilities = ["update"]
}

path "auth/token/revoke-accessor" {
  capabilities = ["update"]
}
```

## Example Usage

```hcl
resource "vault_token" "example" {
  role_name = "app"

  policies = ["policy1", "policy2"]

  renewable = true
  ttl = "24h"

  renew_min_lease = 43200
  renew_increment = 86400

  metadata = {
    "purpose" = "service-account"
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `role_name` - (Optional) The token role name

* `policies` - (Optional) List of policies to attach to this token

* `no_parent` - (Optional) Flag to create a token without parent

* `no_default_policy` - (Optional) Flag to not attach the default policy to this token

* `renewable` - (Optional) Flag to allow to renew this token

* `ttl` - (Optional) The TTL period of this token. This is specified as a numeric string with suffix like "30s" ro "5m"

* `explicit_max_ttl` - (Optional) The explicit max TTL of this token. This is specified as a numeric string with suffix like "30s" ro "5m"

* `display_name` - (Optional) String containing the token display name

* `num_uses` - (Optional) The number of allowed uses of this token

* `period` - (Optional) The period of this token. This is specified as a numeric string with suffix like "30s" ro "5m"

* `renew_min_lease` - (Optional) The minimal lease to renew this token

* `renew_increment` - (Optional) The renew increment. This is specified in seconds

* `metadata` - (Optional) Metadata to be set on this token

* `entity_alias` - (Optional) The entity alias to associate with the token. Must be used with a token role (`role_name` must be set) and the role must have the alias in `allowed_entity_aliases`.

## Attributes Reference

* `lease_duration` - String containing the token lease duration if present in state file

* `lease_started` - String containing the token lease started time if present in state file

* `client_token` - String containing the client token if stored in present file

## Import

Tokens can be imported using its `id` as accessor id, e.g.

```
$ terraform import vault_token.example <accessor_id>
```
