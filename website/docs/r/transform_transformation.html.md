---
layout: "vault"
page_title: "Vault: vault_transform_transformation resource"
sidebar_current: "docs-vault-resource-transform-transformation"
description: |-
  "/transform/transformation/{name}"
---

# vault\_transform\_transformation

This resource supports the "/transform/transformation/{name}" Vault endpoint.

It creates or updates a transformation with the given name. If a transformation with the name does not exist,
it will be created. If the transformation exists, it will be updated with the new attributes.

## Example Usage

```hcl
resource "vault_mount" "example" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_transformation" "example" {
  path          = vault_mount.example.path
  name          = "ccn-fpe"
  type          = "fpe"
  template      = "ccn"
  tweak_source  = "internal"
  allowed_roles = ["payments"]
}
```

### Tokenization Example

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_transformation" "tokenization" {
  path          = vault_mount.transform.path
  name          = "ssn-tokenization"
  type          = "tokenization"
  mapping_mode  = "default"
  stores        = ["my-store"]
  allowed_roles = ["payments"]
}
```

### FPE with Convergent Encryption

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_transformation" "convergent_fpe" {
  path          = vault_mount.transform.path
  name          = "ccn-convergent"
  type          = "fpe"
  template      = "builtin/creditcardnumber"
  tweak_source  = "internal"
  convergent    = true
  allowed_roles = ["payments"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) Path to where the back-end is mounted within Vault.
* `allowed_roles` - (Optional) The set of roles allowed to perform this transformation.
* `masking_character` - (Optional) The character used to replace data when in masking mode
* `name` - (Required) The name of the transformation.
* `template` - (Optional) The name of the template to use.
* `templates` - (Optional) Templates configured for transformation.
* `tweak_source` - (Optional) The source of where the tweak value comes from. Only valid when in FPE mode.
* `type` - (Optional) The type of transformation to perform.
* `deletion_allowed` - (Optional) If true, this transform can be deleted.
  Otherwise, deletion is blocked while this value remains false. Default: `false`
  *Only supported on vault-1.12+*
* `mapping_mode` - (Optional) Specifies the mapping mode for stored values. 
  Can be "default" or "exportable". Only used when `type` is "tokenization".
  **Note:** This field is immutable and cannot be changed after creation. Changing this value will force recreation of the resource.
* `stores` - (Optional) List of stores to use for tokenization state. 
  Only used when `type` is "tokenization".
  **Note:** This field is immutable and cannot be changed after creation. Changing this value will force recreation of the resource.
* `convergent` - (Optional) If true, multiple transformations of the same plaintext will 
  produce the same ciphertext. Only used when `type` is "fpe". Default: `false`

## Tutorials

Refer to the [Codify Management of Vault Enterprise Using Terraform](https://learn.hashicorp.com/tutorials/vault/codify-mgmt-enterprise) tutorial for additional examples of configuring data transformation using the Transform secrets engine.
