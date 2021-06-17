---
layout: "vault"
page_title: "Vault: vault_terraform_cloud_secret_role resource"
sidebar_current: "docs-vault-resource-terraform-secret-role"
description: |-
  Manages a Terraform Cloud secrets role for a Terraform Cloud secrets engine in Vault.
---

# vault\_terraform\_cloud\_secret\_backend\_role

Manages a Terraform Cloud secrets role for a Terraform Cloud secrets engine in Vault.
Terraform Cloud secret backends can then issue Terraform Cloud tokens.

## Example Usage

```hcl
resource "vault_terraform_cloud_secret_backend" "test" {
  backend     = "terraform"
  description = "Manages the Terraform Cloud backend"
  token       = "V0idfhi2iksSDU234ucdbi2nidsi..."
}

resource "vault_terraform_cloud_secret_role" "example" {
  backend      = vault_terraform_cloud_secret_backend.test.backend
  name         = "test-role"
  organization = "example-organization-name"
  team_id      = "team-ieF4isC..."
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Optional) The unique name of an existing Terraform Cloud secrets backend mount. Must not begin or end with a `/`.

* `name` - (Required) The name of the Terraform Cloud secrets engine role to create.

* `organization` - (Optional) The organization name managing your Terraform Cloud instance.
  
* `team_id` - (Optional) The id of the team you wish to create a token for in your Terraform Cloud instance.

* `user_id` - (Optional) The user id you wish to create a token for in your Terraform Cloud instance. (Note: this value can not be provided in conjunction with `team_id` and/or `organization`)

* `max_ttl` - (Optional) Maximum TTL for leases associated with this role, in seconds.

* `ttl` - (Optional) Specifies the TTL for this role.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Terraform Cloud secret backend roles can be imported using the `backend`, `/roles/`, and the `name` e.g.

```
$ terraform import vault_terraform_cloud_secret_role.example terraform/roles/my-role
```
