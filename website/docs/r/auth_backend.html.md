---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-auth-backend"
description: |-
  Writes auth methods for Vault
---

# vault\_auth\_backend


## Example Usage

```hcl
resource "vault_auth_backend" "example" {
  type = "github"
}
```

## Argument Reference

The following arguments are supported:

* `type` - (Required) The name of the auth method type

* `path` - (Optional) The path to mount the auth method — this defaults to the name of the type

* `description` - (Optional) A description of the auth method

* `default_lease_ttl_seconds` - (Optional) The default lease duration in seconds.

* `max_lease_ttl_seconds` - (Optional) The maximum lease duration in seconds.

* `listing_visibility` - (Optional) Speficies whether to show this mount in the UI-specific listing endpoint.

* `local` - (Optional) Specifies if the auth method is local only.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `accessor` - The accessor for this auth method

## Import

Auth methods can be imported using the `path`, e.g.

```
$ terraform import vault_auth_backend.example github
```
