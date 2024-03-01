---
layout: "vault"
page_title: "Vault: vault_plugin_pinned_version resource"
sidebar_current: "docs-vault-plugin-pinned-version"
description: |-
  Manage pinned plugin version registered in the plugin catalog.
---

# vault\_plugin\_pinned\_version

Manages pinned plugin versions registered in the plugin catalog.

~> **Important** All data provided in the resource configuration will be
written in cleartext to state and plan files generated by Terraform, and
will appear in the console output when Terraform runs. Protect these
artifacts accordingly. See
[the main provider documentation](../index.html)
for more details.

For more information on managing external plugins, please refer to the Vault
[documentation](https://developer.hashicorp.com/vault/docs/plugins).

## Example Usage

```hcl
resource "vault_plugin" "jwt" {
  type    = "auth"
  name    = "jwt"
  command = "vault-plugin-auth-jwt"
  version = "v0.17.0"
  sha256  = "6bd0a803ed742aa3ce35e4fa23d2c8d550e6c1567bf63410cec489c28b68b0fc"
  env     = [
    "HTTP_PROXY=http://proxy.example.com:8080"
  ]
}

resource "vault_plugin_pinned_version" "jwt_pin" {
  type    = vault_plugin.jwt.type
  name    = vault_plugin.jwt.name
  version = vault_plugin.jwt.version
}

resource "vault_auth_backend" "jwt_auth" {
  type = vault_plugin_pinned_version.jwt_pin.name
}
```

## Argument Reference

The following arguments are supported:

* `type` - (Required) Type of plugin; one of "auth", "secret", or "database".

* `name` - (Required) Name of the plugin.

* `version` - (Required) Semantic version of the plugin to pin.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Pinned plugin versions can be imported using `type/name` as the ID, e.g.

```
$ terraform import vault_plugin_pinned_version.jwt_pin auth/jwt
```