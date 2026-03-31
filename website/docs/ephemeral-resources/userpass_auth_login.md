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

* `mount` - (Optional) The mount path for the Userpass auth engine in Vault.
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

### Token Settings

For more information on token settings, see the [Token Fields documentation](/docs/providers/vault/index.html#token-fields).

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in seconds. 
  Its current value will be referenced at renewal time.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in seconds. 
  Its current value will be referenced at renewal time.

* `token_period` - (Optional) The maximum allowed period value when a periodic token is requested from this role.

* `token_policies` - (Optional) List of policies to encode onto generated tokens. Depending 
  on the auth method, this list may be supplemented by user/group/other values.

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks of IP 
  addresses which can authenticate successfully, and ties the resulting token to these blocks 
  as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an explicit max TTL onto the token 
  in seconds. This is a hard cap even if `token_ttl` and `token_max_ttl` would otherwise allow 
  a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on 
  generated tokens; otherwise it will be added to the policies set in `token_policies`.

* `token_num_uses` - (Optional) The maximum number of times a generated token may be used 
  (within its lifetime); 0 means unlimited. If you require the token to have the ability to 
  create child tokens, you will need to set this value to 0.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

* `alias_metadata` - (Optional) A map of string to string that will be set as metadata on
  the identity alias. **Note:** This field is only supported in Vault Enterprise 1.21.0 and above.
  If configured for vault ent version lesser than 1.21.0, this field will be ignored, even though the value is persisted in the state file.
  *Available only for Vault Enterprise*.