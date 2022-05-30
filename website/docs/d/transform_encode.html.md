---
layout: "vault"
page_title: "Vault: vault_transform_encode data source"
sidebar_current: "docs-vault-datasource-transform-encode"
description: |-
  "/transform/encode/{role_name}"
---

# vault\_transform\_encode

This data source supports the "/transform/encode/{role_name}" Vault endpoint.

It encodes the provided value using a named role.

## Example Usage

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}
resource "vault_transform_transformation" "ccn-fpe" {
  path          = vault_mount.transform.path
  name          = "ccn-fpe"
  type          = "fpe"
  template      = "builtin/creditcardnumber"
  tweak_source  = "internal"
  allowed_roles = ["payments"]
}
resource "vault_transform_role" "payments" {
  path            = vault_transform_transformation.ccn-fpe.path
  name            = "payments"
  transformations = ["ccn-fpe"]
}
data "vault_transform_encode_role" "test" {
    path        = vault_transform_role.payments.path
    role_name   = "payments"
    batch_input = [{"value":"1111-2222-3333-4444"}]
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) Path to where the back-end is mounted within Vault.
* `batch_input` - (Optional) Specifies a list of items to be encoded in a single batch. If this parameter is set, the parameters 'value', 'transformation' and 'tweak' will be ignored. Each batch item within the list can specify these parameters instead.
* `batch_results` - (Optional) The result of encoding a batch.
* `encoded_value` - (Optional) The result of encoding a value.
* `role_name` - (Required) The name of the role.
* `transformation` - (Optional) The transformation to perform. If no value is provided and the role contains a single transformation, this value will be inferred from the role.
* `tweak` - (Optional) The tweak value to use. Only applicable for FPE transformations
* `value` - (Optional) The value in which to encode.
