---
layout: "vault"
page_title: "Vault: ephemeral vault_alicloud_access_credentials data resource"
sidebar_current: "docs-vault-ephemeral-alicloud-access-credentials"
description: |-
  Generate ephemeral AliCloud credentials from the Vault AliCloud Secrets engine

---

# vault_alicloud_access_credentials (Ephemeral)

Generates ephemeral AliCloud credentials for a role managed by the AliCloud Secrets Engine.  
These credentials are not stored in Terraform state and are automatically managed by Vault.

For more information, refer to
the [Vault AliCloud Secrets Engine documentation](https://developer.hashicorp.com/vault/docs/secrets/alicloud).

## Example Usage

### STS Token Credentials

```hcl
resource "vault_mount" "alicloud" {
  path        = "alicloud-test"
  type        = "alicloud"
  description = "AliCloud secrets engine for testing"
}
resource "vault_alicloud_secret_backend" "example" {
  mount         = vault_mount.alicloud.path
  access_key = var.alicloud_access_key
  secret_key = var.alicloud_secret_key
}

resource "vault_alicloud_secret_backend_role" "example" {
  mount         = vault_mount.alicloud.path
  name     = "my-role"
  role_arn = var.alicloud_role_arn

  policy_document = jsonencode({
    Version = "1"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ecs:DescribeInstances"
      ]
      Resource = "*"
    }]
  })
}

ephemeral "vault_alicloud_access_credentials" "example" {
  mount = vault_alicloud_secret_backend.example.path
  role  = vault_alicloud_secret_backend_role.example.name
  mount_id  = vault_mount.alicloud.id
}

```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Mount path for the AliCloud secret engine in Vault.

* `role` - (Required) AliCloud Secret Role to read credentials from.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `access_key` - The AliCloud access key ID.

* `secret_key` - The AliCloud secret access key.

* `security_token` - The AliCloud security token (STS credentials).

* `expiration` - Time at which the credentials will expire.

* `lease_id` - The lease identifier assigned by Vault.

* `lease_duration` - Lease duration in seconds relative to `lease_start_time`.

* `lease_start_time` - Time at which the lease was acquired, using the system clock where Terraform was running.

* `lease_renewable` - True if the lease duration can be extended through renewal.
