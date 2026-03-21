---
layout: "vault"
page_title: "Vault: vault_keymgmt_aws_kms resource"
sidebar_current: "docs-vault-resource-keymgmt-aws-kms"
description: |-
  Manages AWS KMS provider in the Vault Key Management secrets engine
---

# vault\_keymgmt\_aws\_kms

Manages an AWS KMS provider in the Vault Key Management secrets engine. This resource configures Vault to integrate with AWS Key Management Service, allowing keys created in Vault to be distributed to AWS KMS for use in AWS services.

Once configured, keys can be distributed to AWS KMS using the `vault_keymgmt_distribute_key` resource.

~> **Important** This resource requires **Terraform 1.11+** for write-only attribute support.
The `credentials_wo` field is write-only and will never be stored in Terraform state.
See [the main provider documentation](../index.html) for more details.

For more information on managing AWS KMS with Vault, please refer to the Vault [documentation](https://developer.hashicorp.com/vault/docs/secrets/key-management).

**Note** this feature is available only with Vault Enterprise.

## Example Usage

### Basic Configuration

```hcl
resource "vault_mount" "keymgmt" {
  path = "keymgmt"
  type = "keymgmt"
}

resource "vault_keymgmt_aws_kms" "us_west" {
  mount          = vault_mount.keymgmt.path
  name           = "aws-us-west-2"
  key_collection = "us-west-2"

  credentials_wo = {
    access_key = var.aws_access_key_id
    secret_key = var.aws_secret_access_key
  }
  credentials_wo_version = 1
}
```

### Using AWS Environment Variables or IAM Roles

```hcl
# When credentials are not provided, Vault will use AWS SDK's credential chain:
# 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
# 2. Shared credentials file (~/.aws/credentials)
# 3. IAM instance profile (when running on EC2)
# 4. ECS task credentials (when running on ECS)

resource "vault_keymgmt_aws_kms" "production" {
  mount          = vault_mount.keymgmt.path
  name           = "aws-production"
  key_collection = "us-east-1"

  # No credentials - Vault uses AWS credential chain
}

# Distribute a key to AWS KMS
resource "vault_keymgmt_key" "encryption_key" {
  mount = vault_mount.keymgmt.path
  name = "aws-encryption-key"
  type = "aes256-gcm96"
}

resource "vault_keymgmt_distribute_key" "aws_dist" {
  path     = vault_mount.keymgmt.path
  kms_name = vault_keymgmt_aws_kms.production.name
  key_name = vault_keymgmt_key.encryption_key.name
  purpose  = ["encrypt", "decrypt"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured
  [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required, Forces new resource) Path of the Key Management secrets engine mount. Must match the
  `path` of a [`vault_mount`](mount.html) resource with `type = "keymgmt"`. Use
  `vault_mount.keymgmt.path` here.

* `name` - (Required, Forces new resource) Specifies the name of the AWS KMS provider. Cannot be changed after creation.

* `key_collection` - (Required, Forces new resource) Refers to the name of an AWS region. Cannot be changed after creation.

* `credentials_wo` - (Optional, Sensitive, Write-only) The credentials to use for authentication with AWS KMS. Supplying values for this parameter is optional, as credentials may also be specified as environment variables. Credentials provided to this parameter will take precedence over credentials provided via environment variables. This value is write-only and will not be stored in Terraform state.
  The following vaules are supported:
  - `access_key` - (Required) The AWS access key ID. May also be specified by the AWS_ACCESS_KEY_ID environment variable.
  - `secret_key` - (Required) The AWS secret access key. May also be specified by the AWS_SECRET_ACCESS_KEY environment variable.
  - `session_token` - (Optional) The AWS session token. May also be specified by the AWS_SESSION_TOKEN environment variable.
  - `endpoint` - (Optional) The KMS API endpoint to be used to make AWS KMS requests. May also be specified by the AWS_KMS_ENDPOINT environment variable. This is useful when connecting to KMS over a VPC Endpoint. If not set, the secrets engine will use the default API endpoint for the region.

* `credentials_wo_version` - (Optional) Version number for the write-only credentials. Increment this value to trigger a credential rotation. Changing this value will cause the credentials to be re-sent to Vault during the next apply. For more info see [updating write-only attributes](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_write_only_attributes.html#updating-write-only-attributes).

## Import

AWS KMS providers can be imported using the format `{path}/kms/{name}`, e.g.

```
$ terraform import vault_keymgmt_aws_kms.us_west keymgmt/kms/aws-us-west-2
```

> **Note:** Import sets the `mount` attribute from the import ID. The `credentials_wo` and `credentials_wo_version` fields will not be populated as they are not returned by the Vault API. You must supply these values in your configuration after import. The corresponding `vault_mount` resource must also be present in your configuration (or separately imported).