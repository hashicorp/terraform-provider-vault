---
layout: "vault"
page_title: "Vault: vault_transform_template resource"
sidebar_current: "docs-vault-resource-transform-template"
description: |-
  "/transform/template/{name}"
---

# vault\_transform\_template

This resource supports the `/transform/template/{name}` Vault endpoint.

It creates or updates a template with the given name. If a template with the name does not exist,
it will be created. If the template exists, it will be updated with the new attributes.

-> Requires _Vault Enterprise with the Advanced Data Protection Transform Module_.
See [Transform Secrets Engine](https://www.vaultproject.io/docs/secrets/transform)
for more information.

## Example Usage

Please note that the `pattern` below holds a regex. The regex shown
is identical to the one in our [Setup](https://www.vaultproject.io/docs/secrets/transform#setup)
docs, `(\d{4})-(\d{4})-(\d{4})-(\d{4})`. However, due to HCL, the
backslashes must be escaped to appear correctly in Vault. For further
assistance escaping your own custom regex, see [String Literals](https://www.terraform.io/docs/configuration/expressions.html#string-literals).

```hcl
resource "vault_mount" "transform" {
  path = "transform"
  type = "transform"
}

resource "vault_transform_alphabet" "numerics" {
  path      = vault_mount.transform.path
  name      = "numerics"
  alphabet  = "0123456789"
}

resource "vault_transform_template" "test" {
  path           = vault_transform_alphabet.numerics.path
  name           = "ccn"
  type           = "regex"
  pattern        = "(\\d{4})[- ](\\d{4})[- ](\\d{4})[- ](\\d{4})"
  alphabet       = "numerics"
  encode_format  = "$1-$2-$3-$4"
  decode_formats = {
    "last-four-digits" = "$4"
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `path` - (Required) Path to where the back-end is mounted within Vault.
* `alphabet` - (Optional) The alphabet to use for this template. This is only used during FPE transformations.
* `name` - (Required) The name of the template.
* `pattern` - (Optional) The pattern used for matching. Currently, only regular expression pattern is supported.
* `type` - (Optional) The pattern type to use for match detection. Currently, only regex is supported.
* `encode_format` - (Optional) - The regular expression template used to format encoded values.
  (requires Vault Enterprise 1.9+)
* `decode_formats` - (Optional) - Optional mapping of name to regular expression template, used to customize
  the decoded output. (requires Vault Enterprise 1.9+)
