---
layout: "vault"
page_title: "Vault: ephemeral vault_approle_auth_backend_role_secret_id data resource"
sidebar_current: "docs-vault-ephemeral-approle-auth-backend-role-secret-id"
description: |-
  Generate ephemeral AppRole SecretID from the Vault AppRole Auth backend

---

# vault_approle_auth_backend_role_secret_id (Ephemeral)

Generates an ephemeral AppRole SecretID for a role managed by the AppRole Auth backend.  
These credentials are not stored in Terraform state and are automatically cleaned up by Vault when no longer needed.

This ephemeral resource generates a SecretID that can be used in conjunction with a RoleID to authenticate to Vault via the AppRole auth method. The SecretID is automatically destroyed when the Terraform configuration is no longer active.

For more information, refer to
the [Vault AppRole Auth documentation](https://developer.hashicorp.com/vault/docs/auth/approle).

## Example Usage

### Basic Usage

```hcl
resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "example" {
  backend         = vault_auth_backend.approle.path
  role_name       = "test-role"
  token_policies  = ["default", "dev", "prod"]
}

ephemeral "vault_approle_auth_backend_role_secret_id" "example" {
  backend   = vault_auth_backend.approle.path
  mount_id  = vault_auth_backend.approle.id
  role_name = vault_approle_auth_backend_role.example.role_name
}

# Use the ephemeral SecretID for authentication
resource "vault_approle_auth_backend_login" "login" {
  backend   = vault_auth_backend.approle.path
  role_id   = vault_approle_auth_backend_role.example.role_id
  secret_id = ephemeral.vault_approle_auth_backend_role_secret_id.example.secret_id
}
```

### With CIDR Restrictions

```hcl
ephemeral "vault_approle_auth_backend_role_secret_id" "example" {
  backend   = vault_auth_backend.approle.path
  mount_id  = vault_auth_backend.approle.id
  role_name = vault_approle_auth_backend_role.example.role_name
  cidr_list = ["10.0.0.0/8", "192.168.1.0/24"]
}
```

### With Metadata and TTL

```hcl
ephemeral "vault_approle_auth_backend_role_secret_id" "example" {
  backend   = vault_auth_backend.approle.path
  mount_id  = vault_auth_backend.approle.id
  role_name = vault_approle_auth_backend_role.example.role_name
  
  metadata = jsonencode({
    environment = "production"
    service     = "api-server"
  })
  
  ttl      = 3600  # 1 hour
  num_uses = 10    # Can be used 10 times
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Optional) Path to the mounted AppRole auth backend. Defaults to `approle`.

* `mount_id` - (Optional) If value is set, will defer provisioning the ephemeral resource until
  `terraform apply`. For more details, please refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

* `role_name` - (Required) The name of the role to create the SecretID for.

* `cidr_list` - (Optional) List of CIDR blocks that can log in using the SecretID. If set, specifies blocks of IP addresses which can perform the login operation using this SecretID.

* `metadata` - (Optional) A JSON-encoded string containing metadata in key-value pairs to be set on tokens issued with this SecretID.

* `ttl` - (Optional) The TTL duration of the SecretID in seconds. If not specified, uses the role's `secret_id_ttl`.

* `num_uses` - (Optional) The number of times this SecretID can be used. After this many uses, the SecretID will no longer be valid. If not specified, uses the role's `secret_id_num_uses`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `secret_id` - The generated SecretID. This value is sensitive and ephemeral - it is not stored in Terraform state and is automatically destroyed when the Terraform configuration is no longer active.

* `accessor` - The accessor for the SecretID. This unique ID can be safely logged and used to track or revoke the SecretID.

## Automatic Cleanup

Unlike the regular `vault_approle_auth_backend_role_secret_id` resource, this ephemeral version automatically destroys the SecretID when:

- The Terraform run completes
- The ephemeral resource is no longer referenced in the configuration
- An error occurs during the Terraform apply

This makes it ideal for temporary authentication scenarios where you want to ensure credentials are cleaned up automatically.
