---
layout: "vault"
page_title: "Vault: vault_radius_auth_backend resource"
sidebar_current: "docs-vault-resource-radius-auth-backend"
description: |-
  Manages RADIUS auth backend configuration in Vault.
---

# vault\_radius\_auth\_backend

Configures the RADIUS auth backend in Vault.

The RADIUS auth method allows users to authenticate with Vault using an 
existing RADIUS server that accepts the PAP authentication scheme.

## Example Usage

```hcl
resource "vault_radius_auth_backend" "example" {
  path              = "radius"
  host              = "radius.example.com"
  secret_wo         = "supersecretpassword"
  secret_wo_version = 1
}
```

### With All Options

```hcl
resource "vault_radius_auth_backend" "example" {
  path                       = "my-radius"
  host                       = "radius.example.com"
  port                       = 1812
  secret_wo                  = "supersecretpassword"
  secret_wo_version          = 1
  unregistered_user_policies = ["default", "guest"]
  dial_timeout               = 10
  nas_port                   = 10

  token_ttl                  = 3600
  token_max_ttl              = 7200
  token_policies             = ["default", "radius-users"]
}
```

## Argument Reference

The following arguments are supported:

### Required Arguments

* `host` - (Required) The RADIUS server to connect to. This can be a fully 
  qualified domain name or an IP address.

* `secret_wo` - (Required) The RADIUS shared secret. This is a write-only field 
  and will not be read back from Vault or stored in state.

### Optional Arguments

* `secret_wo_version` - (Optional) The version of the write-only secret. 
  Changing this will trigger an update to the secret in Vault.

* `path` - (Optional) Path to mount the RADIUS auth backend. Defaults to `radius`.

* `port` - (Optional) The UDP port of the RADIUS server. Defaults to `1812`.

* `unregistered_user_policies` - (Optional) A comma-separated list of policies 
  to be granted to unregistered users. Defaults to `""` (empty).

* `dial_timeout` - (Optional) Number of seconds to wait for connecting to the 
  RADIUS server. Defaults to `10`.

* `nas_port` - (Optional) The NAS port field for the RADIUS authentication. 
  Defaults to `10`.

### Common Token Arguments

These arguments are common across several auth methods. Please refer to the
[Vault Token Configuration](/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
documentation for more information.

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in 
  seconds. Defaults to `0`.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in 
  seconds. Defaults to `0`.

* `token_policies` - (Optional) A list of policies applied to tokens issued 
  using this role. Defaults to `[]` (empty).

* `token_bound_cidrs` - (Optional) A list of CIDR blocks. If set, restricts 
  tokens generated using this role to only be usable from these CIDR blocks. 
  Defaults to `[]` (empty).

* `token_explicit_max_ttl` - (Optional) If set, tokens created via this role 
  have an explicit max TTL set on them. Defaults to `0`.

* `token_no_default_policy` - (Optional) If set to `true`, the default policy 
  will not be added to tokens created against this role. Defaults to `false`.

* `token_num_uses` - (Optional) The number of uses for tokens issued via this 
  role, after which they expire. `0` means unlimited. Defaults to `0`.

* `token_period` - (Optional) If set, tokens created via this role are 
  periodic tokens. Defaults to `0`.

* `token_type` - (Optional) The type of tokens to generate. Valid values are 
  `default`, `service`, and `batch`. If not set, uses the mount's tuned default 
  (which unless changed will be `service` tokens).

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `read_timeout` - Number of seconds to wait for a response from the RADIUS server.

* `nas_identifier` - The NAS identifier field for the RADIUS authentication.

## Import

RADIUS auth backends can be imported using the `path`:

```
$ terraform import vault_radius_auth_backend.example radius
$ terraform import vault_radius_auth_backend.example my-radius
```
