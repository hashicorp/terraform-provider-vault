---
layout: "vault"
page_title: "Vault: vault_transit_cmac data source"
sidebar_current: "docs-vault-datasource-transit-cmac"
description: |-
  Generate CMAC using a Vault Transit CMAC key
---

# vault\_transit\_cmac

This is a data source which can be used to generate a CMAC using a Vault Transit key.

## Example Usage

```hcl
data "vault_transit_cmac" "test" {
  path        = "transit"
  name        = "test"
  input       = "aGVsbG8gd29ybGQ="
}
```

## Argument Reference

Each document configuration may have one or more `rule` blocks, which each accept the following arguments:

* `name` - (Required) Specifies the name of the key to use.

* `path` - (Required) The path the transit secret backend is mounted at, with no leading or trailing `/`.

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `key_version` - (Optional) Specifies the version of the key to use for
  CMAC. If not set, uses the latest version. Must be greater than or equal
  to the key's `min_encryption_version`, if set.

* `input` - (Optional) Specifies the **base64 encoded** input data. One of
  `input` or `batch_input` must be supplied.

* `mac_length` - (Optional) Specifies the MAC length to use (POST body parameter).
  The `mac_length` cannot be larger than the cipher's block size.

* `url_mac_length` - (Optional) Specifies the MAC length to use (URL parameter).
  If provided, this value overrides `mac_length`. The `url_mac_length` cannot
  be larger than the cipher's block size.

* `reference` - (Optional)
  A user-supplied string that will be present in the `reference` field on the
  corresponding `batch_results` item in the response, to assist in understanding
  which result corresponds to a particular input. Only valid on batch requests
  when using ‘batch_input’ below.

* `batch_input` - (Optional) Specifies a list of items for processing.
  When this parameter is set, any supplied 'input' or 'context' parameters will be
  ignored. Responses are returned in the 'batch_results' array component of the
  'data' element of the response. Any batch output will preserve the order of the
  batch input. If the input data value of an item is invalid, the
  corresponding item in the 'batch_results' will have the key 'error' with a value
  describing the error. The format for batch_input is:

  ```json
  {
    "batch_input": [
      {
        "input": "adba32=="
      },
      {
        "input": "aGVsbG8gd29ybGQuCg=="
      }
    ]
  }
  ```
  
## Attributes Reference

* `cmac` - The CMAC returned from Vault if using `input`

* `batch_results` - The results returned from Vault if using `batch_input`
