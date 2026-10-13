---
layout: "vault"
page_title: "Vault: vault_transform_rewrap data source"
sidebar_current: "docs-vault-datasource-transform-rewrap"
description: |-
  "/transform/rewrap/{role_name}"
---

# vault\_transform\_rewrap

This data source supports the "/transform/rewrap/{role_name}" Vault endpoint.

It rewraps a value that was encoded with one FPE transformation by decoding it
with the source transformation and re-encoding it with a destination transformation.
Both transformations must be FPE transformations.

## Example Usage

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}
resource "vault_transform_transformation" "ccn-fpe-src" {
  path          = vault_mount.transform.path
  name          = "ccn-fpe-src"
  type          = "fpe"
  template      = "builtin/creditcardnumber"
  tweak_source  = "internal"
  allowed_roles = ["payments"]
}
resource "vault_transform_transformation" "ccn-fpe-dst" {
  path          = vault_mount.transform.path
  name          = "ccn-fpe-dst"
  type          = "fpe"
  template      = "builtin/creditcardnumber"
  tweak_source  = "internal"
  allowed_roles = ["payments"]
}
resource "vault_transform_role" "payments" {
  path            = vault_transform_transformation.ccn-fpe-src.path
  name            = "payments"
  transformations = ["ccn-fpe-src", "ccn-fpe-dst"]
}
data "vault_transform_encode" "encoded" {
  path           = vault_transform_role.payments.path
  role_name      = "payments"
  transformation = vault_transform_transformation.ccn-fpe-src.name
  value          = "1111-2222-3333-4444"
}
data "vault_transform_rewrap" "test" {
  path                  = vault_transform_role.payments.path
  role_name             = "payments"
  transformation        = vault_transform_transformation.ccn-fpe-dst.name
  decode_transformation = vault_transform_transformation.ccn-fpe-src.name
  value                 = data.vault_transform_encode.encoded.encoded_value
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Required) Path to where the back-end is mounted within Vault.
* `role_name` - (Required) The name of the role.
* `value` - (Optional) The value to rewrap. Ignored when `batch_input` is set.
* `transformation` - (Optional) The destination FPE transformation to use for re-encoding the value. If no value is provided and the role contains a single transformation, this value will be inferred from the role.
* `decode_transformation` - (Optional) The source FPE transformation used to decode the value before re-encoding it.
* `tweak` - (Optional) The tweak value to use for re-encoding. Only applicable for FPE transformations with a `supplied` tweak source. Ignored when `batch_input` is set.
* `decode_tweak` - (Optional) The tweak value to use for decoding the source value. Only applicable for FPE transformations with a `supplied` tweak source. Ignored when `batch_input` is set.
* `batch_input` - (Optional) Specifies a list of items to be rewrapped in a single batch. If this parameter is set, the top-level parameters `value`, `transformation`, `decode_transformation`, `tweak`, and `decode_tweak` will be ignored. Each batch item within the list can specify these parameters instead.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `encoded_value` - The result of rewrapping a value. Only populated for single-value requests (when `batch_input` is not set).
* `tweak` - The tweak value used or generated during re-encoding. Only populated when the destination transformation uses a `generated` or `internal` tweak source.
* `batch_results` - The results of rewrapping a batch of items. Only populated when `batch_input` is set. Each element is a map containing `encoded_value` and, if applicable, `tweak`.
