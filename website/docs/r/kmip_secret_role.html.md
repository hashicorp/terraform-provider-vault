---
layout: "vault"
page_title: "Vault: vault_kmip_secret_role resource"
sidebar_current: "docs-vault-resource-kmip-secret-role"
description: |-
  Provision KMIP Secret roles in Vault.
---

# vault\_kmip\_secret\_role

Manages KMIP Secret roles in a Vault server. This feature requires
Vault Enterprise. See the [Vault documentation](https://www.vaultproject.io/docs/secrets/kmip)
for more information.

## Example Usage

```hcl
resource "vault_kmip_secret_backend" "default" {
  path        = "kmip"
  description = "Vault KMIP backend"
}

resource "vault_kmip_secret_scope" "dev" {
  path  = vault_kmip_secret_backend.default.path
  scope = "dev"
  force = true
}

resource "vault_kmip_secret_role" "admin" {
  path                     = vault_kmip_secret_scope.dev.path
  scope                    = vault_kmip_secret_scope.dev.scope
  role                     = "admin"
  tls_client_key_type      = "ec"
  tls_client_key_bits      = 256
  operation_activate       = true
  operation_get            = true
  operation_get_attributes = true
  operation_create         = true
  operation_destroy        = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) The unique path this backend should be mounted at. Must
  not begin or end with a `/`. Defaults to `kmip`.

* `scope` - (Required) Name of the scope.

* `role` - (Required) Name of the role.

* `tls_client_key_type` - (Optional) Client certificate key type, `rsa` or `ec`.

* `tls_client_key_bits` - (Optional) Client certificate key bits, valid values depend on key type.

* `tls_client_ttl` - (Optional) Client certificate TTL in seconds.

* `operation_activate` - (Optional) Grant permission to use the KMIP Activate operation.

* `operation_add_attribute` - (Optional) Grant permission to use the KMIP Add Attribute operation.

* `operation_all` - (Optional) Grant all permissions to this role. May not be specified with any other `operation_*` params.

* `operation_create` - (Optional) Grant permission to use the KMIP Create operation.

* `operation_create_key_pair` - (Optional) Grant permission to use the KMIP Create Key Pair operation.

* `operation_decrypt` - (Optional) Grant permission to use the KMIP Decrypt operation.

* `operation_delete_attribute` - (Optional) Grant permission to use the KMIP Delete Attribute operation.

* `operation_destroy` - (Optional) Grant permission to use the KMIP Destroy operation.

* `operation_discover_versions` - (Optional) Grant permission to use the KMIP Discover Version operation.

* `operation_encrypt` - (Optional) Grant permission to use the KMIP Encrypt operation.

* `operation_get` - (Optional) Grant permission to use the KMIP Get operation.

* `operation_get_attribute_list` - (Optional) Grant permission to use the KMIP Get Atrribute List operation.

* `operation_get_attributes` - (Optional) Grant permission to use the KMIP Get Atrributes operation.

* `operation_import` - (Optional) Grant permission to use the KMIP Import operation.

* `operation_locate` - (Optional) Grant permission to use the KMIP Get Locate operation.

* `operation_mac` - (Optional) Grant permission to use the KMIP MAC operation.

* `operation_mac_verify` - (Optional) Grant permission to use the KMIP MAC Verify operation.

* `operation_modify_attribute` - (Optional) Grant permission to use the KMIP Modify Attribute operation.

* `operation_none` - (Optional) Remove all permissions from this role. May not be specified with any other `operation_*` params.

* `operation_query` - (Optional) Grant permission to use the KMIP Query operation.

* `operation_register` - (Optional) Grant permission to use the KMIP Register operation.

* `operation_rekey` - (Optional) Grant permission to use the KMIP Rekey operation.

* `operation_rekey_key_pair` - (Optional) Grant permission to use the KMIP Rekey Key Pair operation.

* `operation_revoke` - (Optional) Grant permission to use the KMIP Revoke operation.

* `operation_rng_retrieve` - (Optional) Grant permission to use the KMIP RNG Retrieve operation.

* `operation_rng_seed` - (Optional) Grant permission to use the KMIP RNG Seed operation.

* `operation_sign` - (Optional) Grant permission to use the KMIP Sign operation.

* `operation_signature_verify` - (Optional) Grant permission to use the KMIP Signature Verify operation.


## Attributes Reference

No additional attributes are exported by this resource.

## Import

KMIP Secret role can be imported using the `path`, e.g.

```
$ terraform import vault_kmip_secret_role.admin kmip
```
