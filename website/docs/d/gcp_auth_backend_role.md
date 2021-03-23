---
layout: "vault"
page_title: "Vault: vault_gcp_auth_backend_role data source"
sidebar_current: "docs-vault-datasource-gcp-auth-backend-role"
description: |-
  Manages GCP auth backend roles in Vault.
---

# vault\_gcp\_auth\_backend\_role

Reads a GCP auth role from a Vault server.

## Example Usage

```hcl
data "vault_gcp_auth_backend_role" "role" {
  backend   = "my-gcp-backend"
  role_name = "my-role"
}

output "role-id" {
  value = "${data.vault_gcp_auth_backend_role.role.role_id}"
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role to retrieve the Role ID for.

* `backend` - (Optional) The unique name for the GCP backend from which to fetch the role. Defaults to "gcp".

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `role_id` - The RoleID of the GCP role.

* `type` - Type of GCP role. Expected values are `iam` or `gce`.

* `bound_service_accounts` - GCP service accounts bound to the role. Returned when `type` is `iam`.

* `bound_projects` - GCP projects bound to the role.

* `bound_zones` - GCP zones bound to the role. Returned when `type` is `gce`.

* `bound_regions` - GCP regions bound to the role. Returned when `type` is `gce`.

* `bound_instance_groups` - GCP regions bound to the role. Returned when `type` is `gce`.

* `bound_labels` - GCP labels bound to the role. Returned when `type` is `gce`.

* `token_policies` - Token policies bound to the role.
