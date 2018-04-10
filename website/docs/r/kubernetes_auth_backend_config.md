---
layout: "vault"
page_title: "Vault: vault_kubernetes_auth_backend_config resource"
sidebar_current: "docs-vault-kubernetes-auth-backend-config"
description: |-
  Manages Kubernetes auth backend configs in Vault.
---

# vault\_kubernetes\_auth\_backend\_config

Manages an Kubernetes auth backend config in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/kubernetes.html) for more
information.

## Example Usage

```hcl
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "example" {
  backend   = "${vault_auth_backend.kubernetes.path}"
  kubernetes_host = "http://example.com:443"
  kubernetes_ca_cert = "-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----"
  token_reviewer_jwt = "ZXhhbXBsZQo="
}
```

## Argument Reference

The following arguments are supported:

* `kubernetes_host` - (Required) Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.

* `kubernetes_ca_cert` - (Optional) PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API.

* `token_reviewer_jwt` - (Optional) A service account JWT used to access the TokenReview API to validate other JWTs during login. If not set the JWT used for login will be used to access the API.

* `pem_keys` - (Optional) List of PEM-formatted public keys or certificates used to verify the signatures of Kubernetes service account JWTs. If a certificate is given, its public key will be extracted. Not every installation of Kubernetes exposes these keys. 

## Attributes Reference

No additional attributes are exported by this resource.
