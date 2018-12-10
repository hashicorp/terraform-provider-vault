---
layout: "vault"
page_title: "Vault: vault_github_auth_backend resource"
sidebar_current: "docs-vault-github-auth-backend"
description: |-
  Manages Github Auth mounts in Vault.
---

# vault\_github\_auth\_backend

Manages a Github Auth mount in a Vault server. See the [Vault 
documentation](https://www.vaultproject.io/docs/auth/github.html) for more
information.

## Example Usage

```hcl
resource "vault_github_auth_backend" "example" {
  organization = "myorg"

}
```

## Argument Reference

The following arguments are supported:

* `path` - (Optional) Path where the auth backend is mounted. Defaults to `auth/github` 
  if not specified.

* `organization` - (Required) The organization configured users must be part of.

* `base_url` - (Optional) The API endpoint to use. Useful if you 
  are running GitHub Enterprise or an API-compatible authentication server.

* `description` - (Optional) Specifies the description of the mount. 
  This overrides the current stored value, if any.

* `ttl` - (Optional) Duration after which authentication will be expired,
  in seconds.

* `max_ttl` - (Optional) Maximum duration after which authentication will be expired, 
  in seconds.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Github authentication mounts can be imported using the `path`, e.g.

```
$ terraform import vault_github_auth_backend_role.example auth/github
```
