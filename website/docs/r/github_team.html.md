---
layout: "vault"
page_title: "Vault: vault_github_team resource"
sidebar_current: "docs-vault-github-team"
description: |-
  Manages Team mappings for Github Auth backend mounts in Vault.
---

# vault\_github\_team

Manages policy mappings for Github Teams authenticated via Github. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/github.html) for more
information.

## Example Usage

```hcl
resource "vault_github_auth_backend" "example" {
  organization = "myorg"
}

resource "vault_github_team" "tf_devs" {
  backend        = vault_github_auth_backend.example.id
  team           = "terraform-developers"
  token_policies = ["developer", "read-only"]
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) Path where the github auth backend is mounted. Defaults to `github`
  if not specified.

* `team` - (Required) GitHub team name in "slugified" format, for example: Terraform
  Developers -> `terraform-developers`.

### Common Token Arguments

These arguments are common across several Authentication Token resources since Vault 1.2.

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_policies` - (Optional) List of policies to encode onto generated tokens. Depending
  on the auth method, this list may be supplemented by user/group/other values.

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks of IP
  addresses which can authenticate successfully, and ties the resulting token to these blocks
  as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an
  [explicit max TTL](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token in number of seconds. This is a hard cap even if `token_ttl` and
  `token_max_ttl` would otherwise allow a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on
  generated tokens; otherwise it will be added to the policies set in token_policies.

* `token_num_uses` - (Optional) The
  [period](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls),
  if any, in number of seconds to set on the token.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

### Deprecated Arguments

These arguments are deprecated since Vault 1.2 in favour of the common token arguments
documented above.

* `policies` - (Optional; Deprecated, use `token_policies` instead) An array of strings
  specifying the policies to be set on tokens issued using this role.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Github team mappings can be imported using the `path`, e.g.

```
$ terraform import vault_github_team.tf_devs auth/github/map/teams/terraform-developers
```
