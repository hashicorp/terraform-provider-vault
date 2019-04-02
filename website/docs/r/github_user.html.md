---
layout: "vault"
page_title: "Vault: vault_github_user resource"
sidebar_current: "docs-vault-github-user"
description: |-
  Manages User mappings for Github Auth backend mounts in Vault.
---

# vault\_github\_user

Manages policy mappings for Github Users authenticated via Github. See the [Vault 
documentation](https://www.vaultproject.io/docs/auth/github.html) for more
information.

## Example Usage

```hcl
resource "vault_github_auth_backend" "example" {
  organization = "myorg"
}

resource "vault_github_user" "tf_user" {
  backend = "${vault_github_auth_backend.example.id}"
  user = "john.doe"
  policies = ["developer", "read-only"]
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) Path where the github auth backend is mounted. Defaults to `github` 
  if not specified.

* `user` - (Required) GitHub user name.

* `policies` - (Optional) A list of policies to be assigned to this user.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Github user mappings can be imported using the `path`, e.g.

```
$ terraform import vault_github_user.tf_user auth/github/map/users/john.doe
```
