---
layout: "vault"
page_title: "Vault: vault_kubernetes_service_account_token ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-kubernetes-service-account-token"
description: |-
  Generate Kubernetes service account tokens from Vault
---

# vault\_kubernetes\_service\_account\_token (Ephemeral)

Generates Kubernetes service account tokens dynamically based on a role.

~> **Important** All Vault ephemeral resources are supported from Terraform 1.10+.
Please refer to the [ephemeral resources usage guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources)
for additional information.

## Example Usage

```hcl
resource "vault_kubernetes_secret_backend" "config" {
  path                      = "kubernetes"
  description               = "kubernetes secrets engine"
  kubernetes_host           = "https://127.0.0.1:8443"
  kubernetes_ca_cert        = file("ca_cert.pem")
  service_account_jwt       = file("service_account_jwt")
  disable_local_ca_jwt      = false
}

resource "vault_kubernetes_secret_backend_role" "role" {
  backend                       = vault_kubernetes_secret_backend.config.path
  name                          = "service-account-role"
  allowed_kubernetes_namespaces = ["*"]
  token_max_ttl                 = 43200
  token_default_ttl             = 3600
  service_account_name          = "test-service-account"
  kubernetes_role_type          = "Role"
}

ephemeral "vault_kubernetes_service_account_token" "token" {
  backend              = vault_kubernetes_secret_backend.config.path
  role                 = vault_kubernetes_secret_backend_role.role.name
  kubernetes_namespace = "default"
  mount_id             = vault_kubernetes_secret_backend.config.id
}

# Use the token in another resource
resource "kubernetes_secret" "example" {
  metadata {
    name = "vault-token"
  }

  data = {
    token = ephemeral.vault_kubernetes_service_account_token.token.service_account_token
  }
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) The Kubernetes secret backend to generate service account tokens from.

* `role` - (Required) The name of the role.

* `kubernetes_namespace` - (Required) The name of the Kubernetes namespace in which to generate the credentials.

* `cluster_role_binding` - (Optional) If true, generate a ClusterRoleBinding to grant permissions across the whole cluster instead of within a namespace.

* `ttl` - (Optional) The TTL of the generated Kubernetes service account token, specified in seconds or as a Go duration format string.

* `namespace` - (Optional) The Vault namespace. See [Vault Namespaces](/docs/enterprise/namespaces/index.html) for more information.

* `mount_id` - (Optional) The ephemeral resource depends on the unknown value `mount_id`, which will
be known only after the related `vault_kubernetes_secret_backend` has been created. Hence, using `mount_id` will defer the provisioning of the ephemeral
resource until the apply step. See the [ephemeral resources usage guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources)
for more details.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `service_account_name` - The name of the service account associated with the token.

* `service_account_namespace` - The Kubernetes namespace that the service account resides in.

* `service_account_token` - The Kubernetes service account token.

* `lease_id` - The lease identifier assigned by Vault.

* `lease_duration` - The duration of the lease in seconds.

* `lease_renewable` - True if the duration of this lease can be extended through renewal.
