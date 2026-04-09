---
layout: "vault"
page_title: "Vault: vault_userpass_auth_login ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-userpass-auth-login"
description: |-
  Log in to Vault using the Userpass auth method.
---

# vault_userpass_auth_login (Ephemeral)

Logs in to Vault using the [Userpass auth method](https://developer.hashicorp.com/vault/docs/auth/userpass)
and returns a short-lived client token. The token is never stored in Terraform
state.

~> **Important** All Vault ephemeral resources are supported from Terraform 1.10+.
Please refer to the [ephemeral resources usage guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources)
for additional information.

## Example Usage

### Basic Login

```hcl
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

resource "vault_userpass_auth_backend_user" "user" {
  mount          = vault_auth_backend.userpass.path
  username       = "example-user"
  password_wo    = "change123"
  token_policies = ["default"]
}

ephemeral "vault_userpass_auth_login" "login" {
  mount    = vault_auth_backend.userpass.path
  mount_id = vault_auth_backend.userpass.id
  username = vault_userpass_auth_backend_user.user.username
  password = "change123"
}

provider "vault" {
  alias = "userpass_auth"
  token = ephemeral.vault_userpass_auth_login.login.client_token
}

data "vault_generic_secret" "lookup_self" {
  provider = vault.userpass_auth
  path     = "auth/token/lookup-self"
}
```

### Login Within a Namespace

```hcl
resource "vault_namespace" "test" {
  path = "team-a"
}

resource "vault_auth_backend" "userpass" {
  type      = "userpass"
  path      = "userpass"
  namespace = vault_namespace.test.path
}

resource "vault_userpass_auth_backend_user" "user" {
  namespace      = vault_namespace.test.path
  mount          = vault_auth_backend.userpass.path
  username       = "example-user"
  password_wo    = "change123"
  token_policies = ["default"]
}

ephemeral "vault_userpass_auth_login" "login" {
  namespace = vault_namespace.test.path
  mount     = vault_auth_backend.userpass.path
  mount_id  = vault_auth_backend.userpass.id
  username  = vault_userpass_auth_backend_user.user.username
  password  = "change123"
}

provider "vault" {
  alias     = "userpass_auth"
  token     = ephemeral.vault_userpass_auth_login.login.client_token
  namespace = vault_namespace.test.path
}

data "vault_generic_secret" "lookup_self" {
  provider = vault.userpass_auth
  path     = "auth/token/lookup-self"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The Vault namespace to log in to.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) The mount path for the Userpass auth engine in Vault.
  Defaults to `userpass`.

* `mount_id` - (Optional) An opaque value used to defer provisioning of the
  ephemeral resource until `terraform apply`. Set this to the auth mount ID to
  ensure the mount exists before the ephemeral login is attempted.

* `username` - (Required) Username to log in with.

* `password` - (Required, Sensitive) Password to log in with.



## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `client_token` - (Sensitive) The Vault client token issued after a successful login.

* `accessor` - The accessor for the client token.

* `policies` - The list of policies attached to the client token.

* `lease_duration` - The lease duration of the client token in seconds.

* `renewable` - Whether the client token is renewable.