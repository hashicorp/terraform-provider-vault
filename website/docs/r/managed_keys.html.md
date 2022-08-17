---
layout: "vault"
page_title: "Vault: vault_managed_keys resource"
sidebar_current: "docs-vault-resource-managed-keys"
description: |-
  Configures Managed Keys in Vault
---

# vault\_managed\_keys

A resource that manages the lifecycle of all [Managed Keys](https://www.vaultproject.io/docs/enterprise/managed-keys) in Vault.

**Note** this feature is available only with Vault Enterprise.

## Example Usage

```hcl
resource "vault_managed_keys" "keys" {

  aws {
    name       = "aws-key-1"
    access_key = var.aws_access_key
    secret_key = var.aws_secret_key
    key_bits   = "2048"
    key_type   = "RSA"
    kms_key    = "alias/vault_aws_key_1"
  }

  aws {
    name       = "aws-key-2"
    access_key = var.aws_access_key
    secret_key = var.aws_secret_key
    key_bits   = "4096"
    key_type   = "RSA"
    kms_key    = "alias/vault_aws_key_2"
  }
}

resource "vault_mount" "pki" {
  path                      = "pki"
  type                      = "pki"
  description               = "Example mount for managed keys"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 36000
  allowed_managed_keys      = [
    tolist(vault_managed_keys.keys.aws)[0].name,
    tolist(vault_managed_keys.keys.aws)[1].name
  ]
}
```


## Caveats

This single resource handles the lifecycle of _all_ the managed keys that must be created in Vault.
There can only be one such resource in the TF state, and if there are already provisioned managed
keys in Vault, we recommend using `terraform import` instead.

## Argument Reference

The following arguments are supported:

### Common Parameters

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
  *Available only for Vault Enterprise*.

* `allow_generate_key` - (Optional) If no existing key can be found in 
  the referenced backend, instructs Vault to generate a key within the backend.

* `allow_replace_key` - (Optional) Controls the ability for Vault to replace through
  generation or importing a key into the configured backend even
  if a key is present, if set to `false` those operations are forbidden
  if a key exists.

* `allow_store_key` - (Optional) Controls the ability for Vault to import a key to the
  configured backend, if `false`, those operations will be forbidden.

* `any_mount` - (Optional) If `true`, allows usage from any mount point within the
  namespace.


### AWS Parameters

* `name` - (Required) A unique lowercase name that serves as identifying the key.

* `access_key` - (Required) The AWS access key to use.

* `secret_key` - (Required) The AWS access key to use.

* `key_bits` - (Required) The size in bits for an RSA key.

* `key_type` - (Required) The type of key to use.

* `kms_key` - (Required) An identifier for the key.

* `curve` - (Optional) The curve to use for an ECDSA key. Used when `key_type` 
  is `ECDSA`. Required if `allow_generate_key` is `true`.

* `endpoint` - (Optional) Used to specify a custom AWS endpoint.

* `region` - (Optional) The AWS region where the keys are stored (or will be stored).


### Azure Parameters

**Note** this provider is available only with Vault Enterprise Plus (HSMs).

* `name` - (Required) A unique lowercase name that serves as identifying the key.

* `tenant_id` - (Required) The tenant id for the Azure Active Directory organization.

* `client_id` - (Required) The client id for credentials to query the Azure APIs.

* `client_secret` - (Required) The client secret for credentials to query the Azure APIs.

* `vault_name` - (Required) The Key Vault vault to use for encryption and decryption.

* `key_name` - (Required) The Key Vault key to use for encryption and decryption.

* `key_type` - (Required) The type of key to use.

* `environment` - (Optional) The Azure Cloud environment API endpoints to use.

* `resource` - (Optional) The Azure Key Vault resource's DNS Suffix to connect to.

* `key_bits` - (Optional) The size in bits for an RSA key. This field is required
  when `key_type` is `RSA` or when `allow_generate_key` is `true`


### PKCS Parameters

**Note** this provider is available only with Vault Enterprise Plus (HSMs).

* `name` - (Required) A unique lowercase name that serves as identifying the key.

* `library` - (Required) The name of the kms_library stanza to use from Vault's config
  to lookup the local library path.

* `key_label` - (Required) The label of the key to use.

* `key_id` - (Required) The id of a PKCS#11 key to use.

* `mechanism` - (Required) The encryption/decryption mechanism to use, specified as a
  hexadecimal (prefixed by 0x) string.

* `pin` - (Required) The PIN for login.

* `slot` - (Optional) The slot number to use, specified as a string in a decimal format
  (e.g. `2305843009213693953`).

* `token_label` - (Optional) The slot token label to use.

* `curve` - (Optional) Supplies the curve value when using the `CKM_ECDSA` mechanism.
  Required if `allow_generate_key` is `true`.

* `key_bits` - (Optional) Supplies the size in bits of the key when using `CKM_RSA_PKCS_PSS`,
  `CKM_RSA_PKCS_OAEP` or `CKM_RSA_PKCS` as a value for `mechanism`. Required if
  `allow_generate_key` is `true`.

* `force_rw_session` - (Optional) Force all operations to open up a read-write session to
  the HSM.


## Import

Mounts can be imported using the `id` of `default`, e.g.

```
$ terraform import vault_managed_keys.keys default
```

