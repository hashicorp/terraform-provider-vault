---
layout: "vault"
page_title: "Vault: vault_generic_secret_metadata resource"
sidebar_current: "docs-vault-resource-generic-secret-metadata"
description: |- Set kvv2 secret's metadata for a given path in Vault
---

# vault\_generic\_secret\_metadata

Writes and manages secrets metadata stored in a given path in the vault.

This resource is solely intented to be used with kvv2 secret engine.
[Vault's "generic" secret backend](https://www.vaultproject.io/docs/secrets/generic/index.html)
kv version 2. In kv v1 there are no metadata.

~> **Important** the `custom_metadata` metadata requires vault v1.9.0

## Example Usage

```hcl
resource "vault_generic_secret" "example" {
  path = "secret/foo"

  data_json = jsonencode({
    foo   = "bar",
    pizza = "cheese"
  })
}

resource "vault_generic_secret_metadata" "example" {
  path = vault_generic_secret.example.path
  
  custom_metadata = {
    owners   = "teamA"
    some_key = "some_value"
    blah     = "diblah"
  }
  
  cas_required         = true
  delete_version_after = "12h"
  max_version          = 3
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) The full logical path at which to write the given metadata. To write data into the "generic" secret
  backend mounted in Vault by default, this should be prefixed with `secret/`. Writing to other backends with this
  resource is not possible.

* `cas_required` - (Optional) Boolean. When `true`, writes will only be allowed if the key’s current
  version matches the version specified in the cas parameter. Default to `false` (vault's value)

* `custom_metadata` - (Optional) A map of strings representing the `custom_metadata` metadata field.

* `delete_version_after` - (Optional) A string representing a `time.Duration`. eg: `730h`. This string will be parsed 
  with [ParseDuration](https://pkg.go.dev/time#ParseDuration). Lifetime for a secret's version

* `max_version` - (Optional) A Integer representing the maximum number of version for a given secret. 
  default to 0 (vault's value), unlimited

## Required Vault Capabilities

Use of this resource requires the `create` or `update` capability
(depending on whether the resource already exists) on the given path, the `delete` capability if the resource is removed
from configuration, and the `read` capability for drift detection (by default).

### Drift Detection

This resource does not necessarily need to *read* the secret data back from Terraform on refresh. To avoid the need
for `read` access on the given path set the `disable_read` argument to `true`. This means that Terraform *will not*
be able to detect and repair "drift" on this resource, should the data be updated or deleted outside of Terraform.

## Import

Generic secrets can be imported using the `path`, e.g.

```
$ terraform import vault_generic_secret_metadata.example secret/foo
```
