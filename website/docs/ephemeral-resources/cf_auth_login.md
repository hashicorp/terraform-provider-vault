---
layout: "vault"
page_title: "Vault: vault_cf_auth_login ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-cf-auth-login"
description: |-
  Log in to Vault using the CloudFoundry auth method.
---

# vault\_cf\_auth\_login (Ephemeral)

Logs in to Vault using the [CloudFoundry (CF) auth method](https://developer.hashicorp.com/vault/docs/auth/cf)
and returns a short-lived client token. The token is never stored in Terraform
state.

~> **Important** All Vault ephemeral resources are supported from Terraform 1.10+.
Please refer to the [ephemeral resources usage guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources)
for additional information.

## Example Usage

```hcl
resource "vault_auth_backend" "cf" {
  type = "cf"
  path = "cf"
}

resource "vault_cf_auth_backend_config" "config" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = [trimspace(file(var.ca_cert_file))]
  cf_api_addr              = var.cf_api_addr
  cf_username              = var.cf_username
  cf_password_wo           = var.cf_password
}

resource "vault_cf_auth_backend_role" "role" {
  mount               = vault_auth_backend.cf.path
  name                = "my-role"
  disable_ip_matching = true
  token_policies      = ["default"]

  depends_on = [vault_cf_auth_backend_config.config]
}

ephemeral "vault_cf_auth_login" "login" {
  mount            = vault_auth_backend.cf.path
  mount_id         = vault_auth_backend.cf.id
  role             = vault_cf_auth_backend_role.role.name
  cf_instance_cert = var.cf_instance_cert
  signing_time     = var.signing_time
  signature        = var.signature
}

# Use the ephemeral token with an aliased provider
provider "vault" {
  alias = "cf_auth"
  token = ephemeral.vault_cf_auth_login.login.client_token
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The Vault namespace to log in to.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `role` - (Required) The name of the CF auth role to log in with.

* `cf_instance_cert` - (Required, Sensitive) The full PEM body of the
  `CF_INSTANCE_CERT` file for the CF application instance.

* `signing_time` - (Required) The date and time at which the signature was
  created, in RFC 3339 format (e.g. `2006-01-02T15:04:05Z`).

* `signature` - (Required, Sensitive) The RSA-PSS/SHA256 signature generated
  using `CF_INSTANCE_KEY` over the concatenation of `signing_time`,
  `cf_instance_cert`, and `role`.

* `mount` - (Optional) The mount path for the CF auth engine in Vault.
  Defaults to `cf`.

* `mount_id` - (Optional) An opaque value used to defer provisioning of the
  ephemeral resource until `terraform apply`. Set to `vault_auth_backend.cf.id`
  to ensure Vault has assigned the mount an ID (which happens only after the
  auth backend is created) before the ephemeral login is attempted. See the
  [ephemeral resources usage guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources)
  for more details.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `client_token` - (Sensitive) The Vault client token issued after a successful login.

* `accessor` - The accessor for the client token.

* `policies` - The list of policies attached to the client token.

* `lease_duration` - The lease duration of the client token in seconds.

* `renewable` - Whether the client token is renewable.
