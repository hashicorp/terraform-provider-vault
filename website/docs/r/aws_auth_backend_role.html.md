---
layout: "vault"
page_title: "Vault: vault_aws_auth_backend_role resource"
sidebar_current: "docs-vault-resource-aws-auth-backend-role"
description: |-
  Manages AWS auth backend roles in Vault.
---

# vault\_aws\_auth\_backend\_role

Manages an AWS auth backend role in a Vault server. Roles constrain the
instances or principals that can perform the login operation against the
backend. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/aws.html) for more
information.

## Example Usage

```hcl
resource "vault_auth_backend" "aws" {
  type = "aws"
}

resource "vault_aws_auth_backend_role" "example" {
  backend                        = "${vault_auth_backend.aws.path}"
  role                           = "test-role"
  auth_type                      = "iam"
  bound_ami_id                   = "ami-8c1be5f6"
  bound_account_id               = "123456789012"
  bound_vpc_id                   = "vpc-b61106d4"
  bound_subnet_id                = "vpc-133128f1"
  bound_iam_role_arn             = "arn:aws:iam::123456789012:role/MyRole"
  bound_iam_instance_profile_arn = "arn:aws:iam::123456789012:instance-profile/MyProfile"
  inferred_entity_type           = "ec2_instance"
  inferred_aws_region            = "us-east-1"
  ttl                            = 60
  max_ttl                        = 120
  policies                       = ["default", "dev", "prod"]
}
```

## Argument Reference

The following arguments are supported:

* `role` - (Required) The name of the role.

* `auth_type` - (Optional) The auth type permitted for this role. Valid choices
  are `ec2` and `iam`. Defaults to `iam`.

* `bound_ami_id` - (Optional) If set, defines a constraint on the EC2 instances
  that can perform the login operation that they should be using the AMI ID
  specified by this field. `auth_type` must be set to `ec2` or
  `inferred_entity_type` must be set to `ec2_instance` to use this constraint.

* `bound_account_id` - (Optional) If set, defines a constraint on the EC2
  instances that can perform the login operation that they should be using the
  account ID specified by this field. `auth_type` must be set to `ec2` or
  `inferred_entity_type` must be set to `ec2_instance` to use this constraint.

* `bound_region` - (Optional) If set, defines a constraint on the EC2 instances
  that can perform the login operation that the region in their identity
  document must match the one specified by this field. `auth_type` must be set
  to `ec2` or `inferred_entity_type` must be set to `ec2_instance` to use this
  constraint.

* `bound_vpc_id` - (Optional) If set, defines a constraint on the EC2 instances
  that can perform the login operation that they be associated with the VPC ID
  that matches the value specified by this field. `auth_type` must be set to
  `ec2` or `inferred_entity_type` must be set to `ec2_instance` to use this
  constraint.

* `bound_subnet_id` - (Optional) If set, defines a constraint on the EC2
  instances that can perform the login operation that they be associated with
  the subnet ID that matches the value specified by this field. `auth_type`
  must be set to `ec2` or `inferred_entity_type` must be set to `ec2_instance`
  to use this constraint.

* `bound_iam_role_arn` - (Optional) If set, defines a constraint on the EC2
  instances that can perform the login operation that they must match the IAM
  role ARN specified by this field. `auth_type` must be set to `ec2` or
  `inferred_entity_type` must be set to `ec2_instance` to use this constraint.

* `bound_iam_instance_profile_arn` - (Optional) If set, defines a constraint on
  the EC2 instances that can perform the login operation that they must be
  associated with an IAM instance profile ARN which has a prefix that matches
  the value specified by this field. The value is prefix-matched as though it
  were a glob ending in `*`. `auth_type` must be set to `ec2` or
  `inferred_entity_type` must be set to `ec2_instance` to use this constraint.

* `role_tag` - (Optional) If set, enable role tags for this role. The value set
  for this field should be the key of the tag on the EC2 instance. `auth_type`
  must be set to `ec2` or `inferred_entity_type` must be set to `ec2_instance`
  to use this constraint.

* `bound_iam_principal_arn` - (Optional) If set, defines the IAM principal that
  must be authenticated when `auth_type` is set to `iam`. Wildcards are
  supported at the end of the ARN.

* `inferred_entity_type` - (Optional) If set, instructs Vault to turn on
  inferencing. The only valid value is `ec2_instance`, which instructs Vault to
  infer that the role comes from an EC2 instance in an IAM instance profile.
  This only applies when `auth_type` is set to `iam`.

* `inferred_aws_region` - (Optional) When `inferred_entity_type` is set, this
  is the region to search for the inferred entities. Required if
  `inferred_entity_type` is set. This only applies when `auth_type` is set to
  `iam`.

* `resolve_aws_unique_ids` - (Optional) If set to `true`, the
  `bound_iam_principal_arn` is resolved to an [AWS Unique
  ID](http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids)
  for the bound principal ARN. This field is ignored when
  `bound_iam_principal_arn` ends in a wildcard. Resolving to unique IDs more
  closely mimics the behavior of AWS services in that if an IAM user or role is
  deleted and a new one is recreated with the same name, those new users or
  roles won't get access to roles in Vault that were permissioned to the prioer
  principals of the same name. Defaults to `true`. Once set to `true`, this
  cannot be changed to `false`--the role must be deleted and recreated, with
  the value set to `true`.

* `ttl` - (Optional) The TTL period of tokens issued using this role, provided
  as a number of seconds.

* `max_ttl` - (Optional) The maximum allowed lifetime of tokens issued using
  this role, provided as a number of seconds.

* `period` - (Optional) If set, indicates that the token generated using this
  role should never expire. The token should be renewed within the duration
  specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. The maximum allowed lifetime of token issued using this
  role. Specified as a number of seconds.

* `policies` - (Optional) An array of strings specifying the policies to be set
  on tokens issued using this role.

* `allow_instance_migration` - (Optional) If set to `true`, allows migration of
  the underlying instance where the client resides.

* `disallow_reauthentication` - (Optional) IF set to `true`, only allows a
  single token to be granted per instance ID. This can only be set when
  `auth_type` is set to `ec2`.

## Attributes Reference

No additional attributes are exported by this resource.
