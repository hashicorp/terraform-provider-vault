---
layout: "vault"
page_title: "Vault: vault_aws_auth_backend_roletag_blacklist resource"
sidebar_current: "docs-vault-resource-aws-auth-backend-roletag-blacklist"
description: |-
  Configures the periodic tidying operation of the blacklisted role tag entries.
---

# vault\_aws\_auth\_backend\_roletag\_blacklist

Configures the periodic tidying operation of the blacklisted role tag entries.

## Example Usage

```hcl
resource "vault_auth_backend" "example" {
  type = "aws"
}

resource "vault_aws_auth_backend_roletag_blacklist" "example" {
  backend       = vault_auth_backend.example.path
  safety_buffer = 360
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) The path the AWS auth backend being configured was
	mounted at.

* `safety_buffer` - (Oprtional) The amount of extra time that must have passed
  beyond the roletag expiration, before it is removed from the backend storage.
  Defaults to 259,200 seconds, or 72 hours.

* `disable_periodic_tidy` - (Optional) If set to true, disables the periodic
  tidying of the roletag blacklist entries. Defaults to false.

## Attributes Reference

No additional attributes are exported by this resource.
