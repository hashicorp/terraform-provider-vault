---
layout: "vault"
page_title: "Vault: vault_kubernetes_auth_backend_role data source"
sidebar_current: "docs-vault-datasource-kubernetes-auth-backend-role"
description: |-
  Manages Kubernetes auth backend roles in Vault.
---

# vault\_kubernetes\_auth\_backend\_role

Reads the Role of an Kubernetes from a Vault server. See the [Vault
documentation](https://www.vaultproject.io/api/auth/kubernetes/index.html#read-role) for more
information.

## Example Usage

```hcl
data "vault_kubernetes_auth_backend_role" "role" {
  backend   = "my-kubernetes-backend"
  role_name = "my-role"
}

output "policies" {
  value = "${data.vault_kubernetes_auth_backend_role.role.policies}"
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role to retrieve the Role attributes for.

* `backend` - (Optional) The unique name for the Kubernetes backend the role to
  retrieve Role attributes for resides in. Defaults to "kubernetes".

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `bound_service_account_names` - List of service account names able to access this role. If set to "*" all names are allowed, both this and bound_service_account_namespaces can not be "*".

* `bound_service_account_namespaces` - List of namespaces allowed to access this role. If set to "*" all namespaces are allowed, both this and bound_service_account_names can not be set to "*".

* `ttl` - The TTL period of tokens issued using this role in seconds.

* `max_ttl` - The maximum allowed lifetime of tokens issued in seconds using this role.

* `num_uses` - Number of times issued tokens can be used. Setting this to 0 or leaving it unset means unlimited uses.

* `period` - If set, indicates that the token generated using this role should never expire. The token should be renewed within the duration specified by this value. At each renewal, the token's TTL will be set to the value of this parameter.

* `policies` - Policies to be set on tokens issued using this role.
