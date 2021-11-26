---
layout: "vault"
page_title: "Vault: vault_aws_auth_backend_identity_whitelist resource"
sidebar_current: "docs-vault-resource-aws-auth-backend-identity-whitelist"
description: |-
  Configures the periodic tidying operation of the whitelisted identity entries.
---

# vault\_aws\_auth\_backend\_identity\_whitelist

Configures the periodic tidying operation of the whitelisted identity entries.

For more information, see the
[Vault docs](https://www.vaultproject.io/api-docs/auth/aws#configure-identity-whitelist-tidy-operation).

## Example Usage

```hcl
resource "vault_auth_backend" "example" {
  type = "aws"
}

resource "vault_aws_auth_backend_identity_whitelist" "example" {
  backend       = vault_auth_backend.example.path
  safety_buffer = 3600
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Optional) The path of the AWS backend being configured.

* `safety_buffer` - (Optional) The amount of extra time, in minutes, that must
  have passed beyond the roletag expiration, before it is removed from the
  backend storage.

* `disable_periodic_tidy` - (Optional) If set to true, disables the periodic
  tidying of the identity-whitelist entries.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

AWS auth backend identity whitelists can be imported using `auth/`, the `backend` path, and `/config/tidy/identity-whitelist` e.g.

```
$ terraform import vault_aws_auth_backend_identity_whitelist.example auth/aws/config/tidy/identity-whitelist
```
