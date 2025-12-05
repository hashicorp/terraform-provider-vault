---
layout: "vault"
page_title: "Vault: ephemeral vault_aws_access_credentials data resource"
sidebar_current: "docs-vault-ephemeral-aws-access-credentials"
description: |-
  Generate ephemeral AWS credentials from the Vault AWS Secrets engine

---

# vault_aws_access_credentials (Ephemeral)

Generates ephemeral AWS credentials for a role managed by the AWS Secrets Engine.  
These credentials are not stored in Terraform state and are automatically managed by Vault.

This ephemeral resource can generate both IAM user credentials and STS (Security Token Service) tokens depending on the role configuration and type parameter.

For more information, refer to
the [Vault AWS Secrets Engine documentation](https://developer.hashicorp.com/vault/docs/secrets/aws).

## Example Usage

### IAM User Credentials

```hcl
resource "vault_aws_secret_backend" "aws" {
  path       = "aws"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
  region     = "us-east-1"
}

resource "vault_aws_secret_backend_role" "example" {
  backend         = vault_aws_secret_backend.aws.path
  name           = "my-role"
  credential_type = "iam_user"
  
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject"
      ]
      Resource = "*"
    }]
  })
}

ephemeral "vault_aws_access_credentials" "example" {
  backend = vault_aws_secret_backend.aws.path
  role    = vault_aws_secret_backend_role.example.name
  type    = "creds"
  region  = "us-east-1"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) Path to the mounted AWS Secrets Engine where the role resides.

* `role` - (Required) The name of the AWS secrets engine role to generate credentials for.

* `type` - (Optional) Type of credentials to generate. Must be either `creds` for IAM user credentials or `sts` for STS tokens. If not specified, defaults to the role's default credential type.

* `role_arn` - (Optional) ARN of the role to assume when `credential_type` is `assumed_role`. Required if the role has multiple ARNs configured.

* `region` - (Optional) AWS region for the generated credentials. If not specified, uses the region configured on the AWS secrets engine.

* `ttl` - (Optional) Time-to-live for STS tokens. Only applicable when `type` is `sts`. Uses the role's `default_sts_ttl` if not specified. Format: `30m`, `1h`, `3600s`, etc.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `access_key` - The AWS access key ID.

* `secret_key` - The AWS secret access key.

* `security_token` - The AWS security token. Only present when `type` is `sts`.

* `lease_id` - The lease identifier assigned by Vault.

* `lease_duration` - Lease duration in seconds relative to `lease_start_time`.

* `lease_start_time` - Time at which the lease was acquired, using the system clock where Terraform was running.

* `lease_renewable` - True if the lease duration can be extended through renewal.
