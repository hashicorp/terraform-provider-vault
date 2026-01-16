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

### Using Standard Secret ID Field

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

### Using Write-Only Secret ID Field (Recommended)

The write-only field provides better security by not persisting the SecretID to state. It can also accept ephemeral values from ephemeral resources:

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

### Using with Ephemeral Resources

```hcl
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "approle"
}

resource "vault_approle_auth_backend_role" "example" {
  backend        = vault_auth_backend.approle.path
  role_name      = "test-role"
  token_policies = ["default", "dev", "prod"]
}

ephemeral "vault_approle_auth_backend_role_secret_id" "secret" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.example.role_name
  mount_id  = vault_approle_auth_backend_role.example.id
}

resource "vault_approle_auth_backend_login" "login" {
  backend              = vault_auth_backend.approle.path
  role_id              = vault_approle_auth_backend_role.example.role_id
  secret_id_wo         = ephemeral.vault_approle_auth_backend_role_secret_id.secret.secret_id
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
  unless `bind_secret_id` is set to false on the role. **Note:** This field is persisted 
  to state. For better security, use `secret_id_wo` instead. Conflicts with `secret_id_wo`.

* `backend` - The unique path of the Vault backend to log in with.

## Ephemeral Attributes

Ephemeral attributes are write-only fields that are not persisted to Terraform state. These attributes can accept ephemeral values from ephemeral resources and provide better security by not storing sensitive credentials. See the [Using Write-Only Attributes guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_write_only_attributes) for more details.

* `secret_id_wo` - (Optional) The secret ID of the role to log in with. Write-only field 
  that is not persisted to state. Can accept ephemeral values. Required unless `bind_secret_id` 
  is set to false on the role. Conflicts with `secret_id`. Requires Terraform Plugin SDK v2.35.0+.

* `secret_id_wo_version` - (Optional) Version counter for the write-only `secret_id_wo` field. 
  Increment this value to trigger re-authentication with a new SecretID when using `secret_id_wo`.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `policies` - A list of policies applied to the token.

* `renewable` - Whether the token is renewable or not.

* `lease_duration` - How long the token is valid for, in seconds.

* `lease_started` - The date and time the lease started, in RFC 3339 format.

* `accessor` - The accessor for the token.

* `client_token` - The Vault token created.

* `metadata` - The metadata associated with the token.
