---
layout: "vault"
page_title: "Vault: ephemeral vault_aws_static_access_credentials data resource"
sidebar_current: "docs-vault-ephemeral-aws-static-access-credentials"
description: |-
  Read ephemeral static AWS credentials from the Vault AWS Secrets engine

---

# vault_aws_static_access_credentials (Ephemeral)

Reads ephemeral static AWS credentials for a static role managed by the AWS Secrets Engine.  
These credentials are not stored in Terraform state and are automatically rotated by Vault.

For more information, refer to
the [Vault AWS Secrets Engine documentation](https://developer.hashicorp.com/vault/docs/secrets/aws).

## Example Usage

```hcl
resource "vault_aws_secret_backend" "aws" {
  path        = "aws"
  description = "AWS Secret Backend"
  access_key  = var.aws_access_key
  secret_key  = var.aws_secret_key
  region      = "us-east-1"
}

resource "vault_aws_secret_backend_static_role" "example" {
  backend         = vault_aws_secret_backend.aws.path
  name            = "my-static-role"
  username        = "vault-static-user"
  rotation_period = "3600"
}

ephemeral "vault_aws_static_access_credentials" "example" {
  mount    = vault_aws_secret_backend.aws.path
  name     = vault_aws_secret_backend_static_role.example.name
  mount_id = vault_aws_secret_backend_static_role.role.id
}
```

## Argument Reference

The following arguments are supported:

* `mount_id` - (Optional) If value is set, will defer provisioning the ephemeral resource until
  `terraform apply`. For more details, please refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where the AWS Secrets Engine is mounted in Vault.

* `name` - (Required) The name of the static role to read credentials for.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `access_key` - The AWS access key ID for the static role.

* `secret_key` - The AWS secret access key for the static role.
