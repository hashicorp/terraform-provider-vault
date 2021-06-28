---
layout: "vault"
page_title: "Vault: vault_aws_auth_backend_role_tag resource"
sidebar_current: "docs-vault-resource-aws-auth-backend-role-tag"
description: |-
  Reads role tags from a Vault AWS auth backend.
---

# vault\_aws\_auth\_backend\_role\_tag

Reads role tag information from an AWS auth backend in Vault. 

## Example Usage

```hcl
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
}

resource "vault_aws_auth_backend_role" "role" {
  backend          = vault_auth_backend.aws.path
  role             = "%s"
  auth_type        = "ec2"
  bound_account_id = "123456789012"
  policies         = ["dev", "prod", "qa", "test"]
  role_tag         = "VaultRoleTag"
}

resource "vault_aws_auth_backend_role_tag" "test" {
  backend     = vault_auth_backend.aws.path
  role        = vault_aws_auth_backend_role.role.role
  policies    = ["prod", "dev", "test"]
  max_ttl     = "1h"
  instance_id = "i-1234567"
}
```

## Argument Reference

The following arguments are supported:

* `role` - (Required) The name of the AWS auth backend role to read
role tags from, with no leading or trailing `/`s.

* `backend` - (Optional) The path to the AWS auth backend to
read role tags from, with no leading or trailing `/`s. Defaults to "aws".

* `policies` - (Optional) The policies to be associated with the tag. Must be a subset of the policies associated with the role.

* `max_ttl` - (Optional) The maximum TTL of the tokens issued using this role.

* `instance_id` - (Optional) Instance ID for which this tag is intended for. If set, the created tag can only be used by the instance with the given ID.

* `allow_instance_migration` - (Optional) If set, allows migration of the underlying instances where the client resides. Use with caution.

* `disallow_reauthentication` - (Optional) If set, only allows a single token to be granted per instance ID.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `tag_key` - The key of the role tag.

* `tag_value` - The value to set the role key.
