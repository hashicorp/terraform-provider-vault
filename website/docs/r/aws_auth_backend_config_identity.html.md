---
layout: "vault"
page_title: "Vault: vault_aws_auth_backend_config_identity resource"
sidebar_current: "docs-vault-resource-aws-auth-backend-config-identity"
description: |-
  Manages AWS auth backend identity configuration in Vault.
---

# vault\_aws\_auth\_backend\_config_identity

Manages an AWS auth backend identity configuration in a Vault server. This configuration defines how Vault interacts
with the identity store. See the [Vault documentation](https://www.vaultproject.io/docs/auth/aws.html) for more
information.

## Example Usage

```hcl
resource "vault_auth_backend" "aws" {
  type = "aws"
}

resource "vault_aws_auth_backend_config_identity" "example" {
  backend      = vault_auth_backend.aws.path
  iam_alias    = "full_arn"
  iam_metadata = ["canonical_arn", "account_id"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `iam_alias` - (Optional) How to generate the identity alias when using the iam auth method. Valid choices are
  `role_id`, `unique_id`, and `full_arn`. Defaults to `role_id`

* `iam_metadata` - (Optional) The metadata to include on the token returned by the `login` endpoint. This metadata will be
  added to both audit logs, and on the `iam_alias`

* `ec2_alias` - (Optional) How to generate the identity alias when using the ec2 auth method. Valid choices are
  `role_id`, `instance_id`, and `image_id`. Defaults to `role_id`

* `ec2_metadata` - (Optional) The metadata to include on the token returned by the `login` endpoint. This metadata will be
  added to both audit logs, and on the `ec2_alias`

## Attributes Reference

No additional attributes are exported by this resource.

## Import

AWS auth backend identity config can be imported using `auth/`, the `backend` path, and `/config/identity` e.g.

```
$ terraform import vault_aws_auth_backend_role.example auth/aws/config/identity
```
