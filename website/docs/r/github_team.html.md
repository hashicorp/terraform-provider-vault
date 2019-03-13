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
  backend = "${vault_github_auth_backend.example.id}"
  team = "terraform-developers"
  policies = ["developer", "read-only"]
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) Path where the github auth backend is mounted. Defaults to `github` 
  if not specified.

* `team` - (Required) GitHub team name in "slugified" format, for example: Terraform Developers -> `terraform-developers`.

* `policies` - (Optional) A list of policies to be assigned to this team.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Github team mappings can be imported using the `path`, e.g.

```
$ terraform import vault_github_team.tf_devs auth/github/map/teams/terraform-developers
```
