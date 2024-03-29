---
layout: "vault"
page_title: "Vault: vault_kubernetes_service_account_token data source"
sidebar_current: "docs-vault-datasource-kubernetes-service-account-token"
description: |-
Generates service account tokens for Kubernetes.
---

# vault\_kubernetes\_service\_account\_token

Generates service account tokens for Kubernetes.

~> **Important** All data retrieved from Vault will be
written in cleartext to state file generated by Terraform, will appear in
the console output when Terraform runs, and may be included in plan files
if secrets are interpolated into any resource attributes.
Protect these artifacts accordingly. See
[the main provider documentation](../index.html)
for more details.

## Example Usage

```hcl
resource "vault_kubernetes_secret_backend" "config" {
  path                      = "kubernetes"
  description               = "kubernetes secrets engine description"
  kubernetes_host           = "https://127.0.0.1:61233"
  kubernetes_ca_cert        = file("/path/to/cert")
  service_account_jwt       = file("/path/to/token")
  disable_local_ca_jwt      = false
}

resource "vault_kubernetes_secret_backend_role" "role" {
  backend                       = vault_kubernetes_secret_backend.config.path
  name                          = "service-account-name-role"
  allowed_kubernetes_namespaces = ["*"]
  token_max_ttl                 = 43200
  token_default_ttl             = 21600
  service_account_name          = "test-service-account-with-generated-token"

  extra_labels = {
    id   = "abc123"
    name = "some_name"
  }
  extra_annotations = {
    env      = "development"
    location = "earth"
  }
}

data "vault_kubernetes_service_account_token" "token" {
  backend              = vault_kubernetes_secret_backend.config.path
  role                 = vault_kubernetes_secret_backend_role.role.name
  kubernetes_namespace = "test"
  cluster_role_binding = false
  ttl                  = "1h"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) The Kubernetes secret backend to generate service account 
  tokens from.

* `role` - (Required) The name of the Kubernetes secret backend role to generate service 
  account tokens from.

* `kubernetes_namespace` - (Required) The name of the Kubernetes namespace in which to 
  generate the credentials.

* `cluster_role_binding` - (Optional) If true, generate a ClusterRoleBinding to grant 
  permissions across the whole cluster instead of within a namespace.

* `ttl` - (Optional) The TTL of the generated Kubernetes service account token, specified in 
  seconds or as a Go duration format string.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `service_account_name` - The name of the service account associated with the token.

* `service_account_namespace` - The Kubernetes namespace that the service account resides in.

* `service_account_token` - The Kubernetes service account token.

* `lease_id` - The lease identifier assigned by Vault.

* `lease_duration` - The duration of the lease in seconds.

* `lease_renewable` - True if the duration of this lease can be extended through renewal.
