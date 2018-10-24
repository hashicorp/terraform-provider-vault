---
layout: "vault"
page_title: "Vault: vault_kubernetes_auth_backend_role resource"
sidebar_current: "docs-vault-kubernetes-auth-backend-role"
description: |-
  Manages Kubernetes auth backend roles in Vault.
---

# vault\_kubernetes\_auth\_backend\_role

Manages an Kubernetes auth backend role in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/kubernetes.html) for more
information.

## Example Usage

```hcl
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_role" "example" {
  backend   = "${vault_auth_backend.kubernetes.path}"
  role_name = "example-role"
  bound_service_account_names = ["example"]
  bound_service_account_namespaces = ["example"]
  ttl = 3600
  policies = ["default", "dev", "prod"]
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) Name of the role.

* `bound_service_account_names` - (Optional) List of service account names able to access this role. If set to "*" all names are allowed, both this and bound_service_account_namespaces can not be "*".

* `bound_service_account_namespaces` - (Optional) List of namespaces allowed to access this role. If set to "*" all namespaces are allowed, both this and bound_service_account_names can not be set to "*".

* `ttl` - (Optional) The TTL period of tokens issued using this role in seconds.

* `max_ttl` - (Optional) The maximum allowed lifetime of tokens issued in seconds using this role.

* `period` - (Optional) If set, indicates that the token generated using this role should never expire. The token should be renewed within the duration specified by this value. At each renewal, the token's TTL will be set to the value of this parameter.

* `policies` - (Optional) Policies to be set on tokens issued using this role.

* `backend` - (Optional) Unique name of the kubernetes backend to configure.

## Attributes Reference

No additional attributes are exported by this resource.
