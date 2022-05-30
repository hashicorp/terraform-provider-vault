---
layout: "vault"
page_title: "Vault: vault_kubernetes_auth_backend_config data source"
sidebar_current: "docs-vault-datasource-kubernetes-auth-backend-config"
description: |-
  Manages Kubernetes auth backend configs in Vault.
---

# vault\_kubernetes\_auth\_backend\_config

Reads the Role of an Kubernetes from a Vault server. See the [Vault
documentation](https://www.vaultproject.io/api-docs/auth/kubernetes#read-config) for more
information.

## Example Usage

```hcl
data "vault_kubernetes_auth_backend_config" "config" {
  backend = "my-kubernetes-backend"
}

output "token_reviewer_jwt" {
  value = data.vault_kubernetes_auth_backend_config.config.token_reviewer_jwt
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Optional) The unique name for the Kubernetes backend the config to
  retrieve Role attributes for resides in. Defaults to "kubernetes".

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `kubernetes_host` - Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.

* `kubernetes_ca_cert` - PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API.

* `pem_keys` - Optional list of PEM-formatted public keys or certificates used to verify the signatures of Kubernetes service account JWTs. If a certificate is given, its public key will be extracted. Not every installation of Kubernetes exposes these keys.

* `issuer` - Optional JWT issuer. If no issuer is specified, `kubernetes.io/serviceaccount` will be used as the default issuer.
