---
layout: "vault"
page_title: "Vault: vault_kubernetes_auth_backend_config resource"
sidebar_current: "docs-vault-resource-kubernetes-auth-backend-config"
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
  backend                = vault_auth_backend.kubernetes.path
  kubernetes_host        = "http://example.com:443"
  kubernetes_ca_cert     = "-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----"
  token_reviewer_jwt     = "ZXhhbXBsZQo="
  issuer                 = "api"
  disable_iss_validation = true
}
```

### Example Usage with Write-Only JWT

```hcl
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "example" {
  backend                       = vault_auth_backend.kubernetes.path
  kubernetes_host               = "http://example.com:443"
  kubernetes_ca_cert            = "-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----"
  token_reviewer_jwt_wo         = var.k8s_token_reviewer_jwt
  token_reviewer_jwt_wo_version = 1
  issuer                        = "api"
  disable_iss_validation        = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
   *Available only for Vault Enterprise*.

* `kubernetes_host` - (Required) Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.

* `kubernetes_ca_cert` - (Optional) PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API.

* `token_reviewer_jwt` - (Optional) A service account JWT (or other token) used as a bearer token to access the TokenReview API to validate other JWTs during login. If not set the JWT used for login will be used to access the API. Conflicts with `token_reviewer_jwt_wo`.

* `token_reviewer_jwt_wo_version` - (Optional) The version of `token_reviewer_jwt_wo` to use during write operations. Required with `token_reviewer_jwt_wo`. For more info see [updating write-only attributes](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_write_only_attributes.html#updating-write-only-attributes).

* `pem_keys` - (Optional) List of PEM-formatted public keys or certificates used to verify the signatures of Kubernetes service account JWTs. If a certificate is given, its public key will be extracted. Not every installation of Kubernetes exposes these keys.

* `issuer` - (Optional) JWT issuer. If no issuer is specified, `kubernetes.io/serviceaccount` will be used as the default issuer.

* `disable_iss_validation` - (Optional) Disable JWT issuer validation. Allows to skip ISS validation. Requires Vault `v1.5.4+` or Vault auth kubernetes plugin `v0.7.1+`

* `disable_local_ca_jwt` - (Optional) Disable defaulting to the local CA cert and service account JWT when running in a Kubernetes pod. Requires Vault `v1.5.4+` or Vault auth kubernetes plugin `v0.7.1+`

* `use_annotations_as_alias_metadata` - (Optional) Use annotations from the client token's associated service account as alias metadata for the Vault entity. Requires Vault `v1.16+` or Vault auth kubernetes plugin `v0.18.0+`

## Ephemeral Attributes Reference

The following write-only attributes are supported:

* `token_reviewer_jwt_wo` - (Optional) A write-only service account JWT (or other token) used as a bearer token to access the 
  TokenReview API to validate other JWTs during login. If not set the JWT used for login will be used to access the API. 
  Conflicts with `token_reviewer_jwt`.
  **Note**: This property is write-only and will not be read from the API.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Kubernetes authentication backend can be imported using the `path`, e.g.

```
$ terraform import vault_kubernetes_auth_backend_config.config auth/kubernetes/config
```
