---
layout: "vault"
page_title: "Vault: vault_address data source"
sidebar_current: "docs-vault-datasource-address"
description: |-
  Fetch the URL of the root of the target Vault server.
---

# vault\_address

Fetch the URL of the root of the target Vault server. Allows getting the URL configured for the provider.

The data source can be useful if the address is configured for the provider with the `VAULT_ADDR` environment variable, or if the URL is needed in a child module using the provider.

## Example Usage

```hcl
data "vault_address" "current" {}
```

## Argument Reference

There are no arguments.

## Attributes Reference

The following attributes are exported:

* `address` - URL of the root of the target Vault server.
