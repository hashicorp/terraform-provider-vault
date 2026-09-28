---
layout: "vault"
page_title: "Vault: vault_transit_decrypt data source"
sidebar_current: "docs-vault-datasource-transit-decrypt"
description: |-
  Decrypt ciphertext using a Vault Transit encryption key.
---

# vault\_transit\_decrypt

This is a data source which can be used to decrypt ciphertext using a Vault Transit key.

## Example Usage

```hcl
data "vault_transit_decrypt" "test" {
  backend     = "transit"
  key         = "test"
  ciphertext  = "vault:v1:S3GtnJ5GUNCWV+/pdL9+g1Feu/nzAv+RlmTmE91Tu0rBkeIU8MEb2nSspC/1IQ=="
}
```

## Argument Reference

Each document configuration may have one or more `rule` blocks, which each accept the following arguments:

* `key` - (Required) Specifies the name of the transit key to decrypt against.

* `backend` - (Required) The path the transit secret backend is mounted at, with no leading or trailing `/`.

* `ciphertext` - (Required) Ciphertext to be decoded.

* `context` - (Optional) Context for key derivation. This is required if key derivation is enabled for this key.

* `hash_algorithm` - (Optional) Specifies the hash algorithm to use for decryption.
  Currently only applies to RSA key types. Default is `sha2-256`. Supported values
  are: `sha1`, `sha2-224`, `sha2-256`, `sha2-384`, `sha2-512`, `sha3-224`,
  `sha3-256`, `sha3-384`, `sha3-512`.

* `padding_scheme` - (Optional) Specifies the RSA encryption padding scheme for
  RSA keys. Default is `oaep`. Supported values are: `oaep`, `pkcs1v15`.

## Attributes Reference

* `plaintext` - Decrypted plaintext returned from Vault
