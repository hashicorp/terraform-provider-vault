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

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Optional) The unique name for the Kubernetes backend the config to
  retrieve Role attributes for resides in. Defaults to "kubernetes".

## Attributes Reference

In addition to the above arguments, the following attributes are exported:

* `kubernetes_host` - Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.

* `kubernetes_ca_cert` - PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API.

* `pem_keys` - Optional list of PEM-formatted public keys or certificates used to verify the signatures of Kubernetes service account JWTs. If a certificate is given, its public key will be extracted. Not every installation of Kubernetes exposes these keys.

* `issuer` - Optional JWT issuer. If no issuer is specified, `kubernetes.io/serviceaccount` will be used as the default issuer.

* `disable_iss_validation` - (Optional) Disable JWT issuer validation. Allows to skip ISS validation. Requires Vault `v1.5.4+` or Vault auth kubernetes plugin `v0.7.1+`

* `disable_local_ca_jwt` - (Optional) Disable defaulting to the local CA cert and service account JWT when running in a Kubernetes pod. Requires Vault `v1.5.4+` or Vault auth kubernetes plugin `v0.7.1+`

* `use_annotations_as_alias_metadata` - (Optional) Use annotations from the client token's associated service account as alias metadata for the Vault entity. Requires Vault `v1.16+` or Vault auth kubernetes plugin `v0.18.0+`
