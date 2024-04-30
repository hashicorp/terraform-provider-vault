---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_key resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-key"
description: |-
  Creates a key on a PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_key

Creates a key on a PKI Secret Backend for Vault.

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path                      = "pki"
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_key" "key" {
  mount    = vault_mount.pki.path
  type     = "exported"
  key_name = "example-key"
  key_type = "rsa"
  key_bits = "2048"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) The path the PKI secret backend is mounted at, with no leading or trailing `/`s.

* `type` - (Required) Specifies the type of the key to create. Can be `exported`,`internal` or `kms`.

* `key_name` - (Optional) When a new key is created with this request, optionally specifies the name for this. 
  The global ref `default` may not be used as a name.

* `key_type` - (Optional) Specifies the desired key type; must be `rsa`, `ed25519` or `ec`.

* `key_bits` - (Optional) Specifies the number of bits to use for the generated keys. 
  Allowed values are 0 (universal default); with `key_type=rsa`, allowed values are:
  2048 (default), 3072, or 4096; with `key_type=ec`, allowed values are: 224, 256 (default), 
  384, or 521; ignored with `key_type=ed25519`.

* `managed_key_name` - (Optional) The managed key's configured name.

* `managed_key_id` - (Optional) The managed key's UUID.


## Attributes Reference

The following attributes are exported:

* `key_id` - ID of the generated key.

## Import

PKI secret backend key can be imported using the `id`, e.g.

```
$ terraform import vault_pki_secret_backend_key.key pki/key/bf9b0d48-d0dd-652c-30be-77d04fc7e94d
```
