---
layout: "vault"
page_title: "Vault: vault_transform_template resource"
sidebar_current: "docs-vault-resource-transform-template"
description: |-
  "/transform/template/{name}"
---

# vault\_transform\_template

This resource supports the "/transform/template/{name}" Vault endpoint.

It creates or updates a template with the given name. If a template with the name does not exist,
it will be created. If the template exists, it will be updated with the new attributes.

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
  path      = vault_transform_alphabet.numerics.path
  name      = "ccn"
  type      = "regex"
  pattern   = "(\\d{4})-(\\d{4})-(\\d{4})-(\\d{4})"
  alphabet  = "numerics"
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) Path to where the back-end is mounted within Vault.
* `alphabet` - (Optional) The alphabet to use for this template. This is only used during FPE transformations.
* `name` - (Required) The name of the template.
* `pattern` - (Optional) The pattern used for matching. Currently, only regular expression pattern is supported.
* `type` - (Optional) The pattern type to use for match detection. Currently, only regex is supported.
