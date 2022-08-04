---
layout: "vault"
page_title: "Vault: vault_auth_backend data source"
sidebar_current: "docs-vault-datasource-auth-backend"
description: |-
  Lookup an Auth Backend from Vault
---

# vault\_auth\_backend

## Example Usage

```hcl
data "vault_auth_backend" "example" {
  path = "userpass"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Required) The auth backend mount point.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `type` - The name of the auth method type.

* `description` - A description of the auth method.

* `default_lease_ttl_seconds` - The default lease duration in seconds.

* `max_lease_ttl_seconds` - The maximum lease duration in seconds.

* `listing_visibility` - Specifies whether to show this mount in the UI-specific listing endpoint.

* `local` - Specifies if the auth method is local only.

* `accessor` - The accessor for this auth method.
