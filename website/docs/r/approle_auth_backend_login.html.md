---
layout: "vault"
page_title: "Vault: vault_approle_auth_backend_login resource"
sidebar_current: "docs-vault-resource-approle-auth-backend-login"
description: |-
  Log into Vault using the AppRole auth backend.
---

# vault\_approle\_auth\_backend\_login

Logs into Vault using the AppRole auth backend. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/approle) for more
information.

## Example Usage

### Standard Usage

```hcl
resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "example" {
  backend         = vault_auth_backend.approle.path
  role_name       = "test-role"
  token_policies  = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "id" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.example.role_name
}

resource "vault_approle_auth_backend_login" "login" {
  backend   = vault_auth_backend.approle.path
  role_id   = vault_approle_auth_backend_role.example.role_id
  secret_id = vault_approle_auth_backend_role_secret_id.id.secret_id
}
```

### Using Write-Only Field

```hcl
resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "example" {
  backend         = vault_auth_backend.approle.path
  role_name       = "test-role"
  token_policies  = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "id" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.example.role_name
}

resource "vault_approle_auth_backend_login" "login" {
  backend              = vault_auth_backend.approle.path
  role_id              = vault_approle_auth_backend_role.example.role_id
  secret_id_wo         = vault_approle_auth_backend_role_secret_id.id.secret_id
  secret_id_wo_version = 1
}
```

### Using Ephemeral Resource (Terraform 1.10+)

```hcl
resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "example" {
  backend         = vault_auth_backend.approle.path
  role_name       = "test-role"
  token_policies  = ["default", "dev", "prod"]
}

ephemeral "vault_approle_auth_backend_role_secret_id" "id" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.example.role_name
}

resource "vault_approle_auth_backend_login" "login" {
  backend      = vault_auth_backend.approle.path
  role_id      = vault_approle_auth_backend_role.example.role_id
  secret_id_wo = ephemeral.vault_approle_auth_backend_role_secret_id.id.secret_id
  secret_id_wo_version = 1
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `role_id` - (Required) The ID of the role to log in with.

* `secret_id` - (Optional) The secret ID of the role to log in with. Required
  unless `bind_secret_id` is set to false on the role.

* `secret_id_wo_version` - (Optional) The version of the `secret_id_wo`. For more info see [updating write-only attributes](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_write_only_attributes.html#updating-write-only-attributes).

* `backend` - The unique path of the Vault backend to log in with.

## Ephemeral Attributes Reference

The following write-only attributes are supported:

* `secret_id_wo` - (Optional) The secret ID of the role to log in with. Write-only attribute that can accept ephemeral values. Required unless `bind_secret_id` is set to false on the role.
  **Note**: This property is write-only and will not be read from the API.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `policies` - A list of policies applied to the token.

* `renewable` - Whether the token is renewable or not.

* `lease_duration` - How long the token is valid for, in seconds.

* `lease_started` - The date and time the lease started, in RFC 3339 format.

* `accessor` - The accessor for the token.

* `client_token` - The Vault token created.

* `metadata` - The metadata associated with the token.
