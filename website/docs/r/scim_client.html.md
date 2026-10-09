---
layout: "vault"
page_title: "Vault: vault_scim_client resource"
sidebar_current: "docs-vault-resource-scim-client"
description: |-
  Manages a SCIM client in Vault Enterprise.
---

# vault\_scim\_client

Manages a SCIM client in Vault. A SCIM client lets an external identity provider
(such as Okta, Entra ID or SailPoint) provision entities, aliases and groups in
Vault through the SCIM 2.0 protocol. Requires Vault Enterprise 2.2.0 or later.
*Available only for Vault Enterprise*.

For more information, see the Vault
[SCIM API documentation](https://developer.hashicorp.com/vault/api-docs/secret/identity/scim).

~> **Important** Vault requires the SCIM feature to be activated with the
`enable-scim` activation flag before SCIM clients can be used. Activation cannot
be undone. See the Vault documentation linked above.

~> **Important** Creating a client first reads its path to make sure the name is
not already in use, so the token used by Terraform needs `read` capability on
`identity/scim/client/*` as well as `create` and `update`.

## Example Usage

### Minimal

```hcl
resource "vault_identity_entity" "scim_operator" {
  name = "scim-operator"
}

resource "vault_scim_client" "okta" {
  client_name = "okta-prod"

  # Vault only accepts SCIM requests from tokens that belong to this entity.
  access_grant_principal = vault_identity_entity.scim_operator.id
}
```

### With all optional arguments

```hcl
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass-scim"
}

resource "vault_auth_backend" "extra" {
  type = "userpass"
  path = "userpass-scim-extra"
}

resource "vault_identity_entity" "scim_operator" {
  name = "scim-operator"
}

resource "vault_scim_client" "okta" {
  client_name            = "okta-prod"
  access_grant_principal = vault_identity_entity.scim_operator.id

  # Auth mount on which login aliases are created for provisioned users.
  alias_mount_accessor = vault_auth_backend.userpass.accessor

  # Further mounts on which this client may manage aliases.
  allowed_extra_alias_mount_accessors = [vault_auth_backend.extra.accessor]

  default_schema_version = "2.2"
  allow_user_adoption    = true
  allow_group_adoption   = true
  max_active_tokens      = 5
  max_token_ttl          = 3600

  # Keep linked entities and groups in Vault when this client is destroyed.
  deletion_policy = "orphan_child_resources"
}
```

## Destroying a client

Deleting a SCIM client that still owns entities or groups needs an explicit
choice, and Vault performs the cleanup in the background. Terraform waits until
the client is gone, up to the `delete` [timeout](#timeouts).

With `deletion_policy` unset, `terraform destroy` **fails** if the client still
owns linked resources, with the error `SCIM client has linked resources`. To
avoid this, set `deletion_policy` and run `terraform apply` **before** running
`terraform destroy`, because the value is read from state at destroy time.

| `deletion_policy` | Effect on linked entities and groups |
|---|---|
| unset | Plain delete. Fails if the client owns any linked resources. |
| `orphan_child_resources` | Unlinks them from the client and keeps them in Vault. |
| `delete_child_resources` | Deletes them together with the client. |

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).

* `client_name` - (Required) The name of the SCIM client. Must be lowercase,
  because Vault lowercases client names when it stores them. Changing this
  forces a new resource.

* `access_grant_principal` - (Required) The ID of the Vault entity authorized to
  call the SCIM protocol endpoints for this client. Each entity can be the
  principal of only one SCIM client.

* `alias_mount_accessor` - (Optional) The accessor of an auth mount on which
  login aliases are created for provisioned users. The mount must not be local
  and must be in the same namespace as the client. It cannot be changed or
  cleared after creation, so changing it forces a new resource.

* `allowed_extra_alias_mount_accessors` - (Optional) A list of additional auth
  mount accessors on which this client may manage aliases. Each mount must not
  be local, must be in the same namespace as the client, and must not be the
  mount set in `alias_mount_accessor`.

* `default_schema_version` - (Optional) The SCIM extension schema version for
  this client. Must be `"2.0"` or `"2.2"`. Defaults to `"2.2"` for new clients.

* `allow_user_adoption` - (Optional) Whether this client may adopt existing
  unmanaged Vault entities. Defaults to `false`.

* `allow_group_adoption` - (Optional) Whether this client may adopt existing
  Vault groups. Defaults to `false`.

* `max_active_tokens` - (Optional) Maximum number of active SCIM tokens for this
  client. Must be at least `1`. Defaults to `2`.

* `max_token_ttl` - (Optional) Maximum TTL, in seconds, of tokens issued for this
  client. Must be at least `0`. `0` uses the cluster default. Defaults to `0`.

* `deletion_policy` - (Optional) Controls how linked entities and groups are
  handled when the client is destroyed. One of `orphan_child_resources` or
  `delete_child_resources`. Leave unset for a plain delete. **This argument is
  tracked in Terraform state only and is never written to Vault.** See
  [Destroying a client](#destroying-a-client).

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The `client_name`. Used as the import ID.

* `client_id` - The unique ID Vault assigned to the client. This is different
  from `id`.

* `deleting` - `true` while Vault is asynchronously cleaning up resources owned
  by this client.

The resource does not export creation or modification timestamps, or counts of
managed entities and groups, because Vault's SCIM client API does not return them.

## Timeouts

This resource supports the following [timeouts](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `delete` - (Default `10m`) How long to wait for Vault to finish removing the
  client. Increase this for clients that own many entities and groups.

## Import

A SCIM client can be imported using its `client_name`, e.g.

```
$ terraform import vault_scim_client.okta okta-prod
```

`deletion_policy` is not stored in Vault, so an import does not set it. Add it
to the configuration and run `terraform apply` before destroying the client.
