---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_issuer resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-issuer"
description: |-
  Manages the lifecycle of an existing issuer on a PKI Secret Backend.
---

# vault\_pki\_secret\_backend\_issuer

Manages the lifecycle of an existing issuer on a PKI Secret Backend. This resource does not
create issuers. It instead tracks and performs updates made to an existing issuer that was
created by one of the PKI generate endpoints. For more information, see the 
[Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/pki#managing-keys-and-issuers)

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path                      = "pki"
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_root_cert" "root" {
  backend     = vault_mount.pki.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
}

resource "vault_pki_secret_backend_issuer" "example" {
  backend     = vault_pki_secret_backend_root_cert.root.backend
  issuer_ref  = vault_pki_secret_backend_root_cert.root.issuer_id
  issuer_name = "example-issuer"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) The path the PKI secret backend is mounted at, with no
  leading or trailing `/`s.

* `issuer_ref` - (Required) Reference to an existing issuer.

* `issuer_name` - (Optional) Name of the issuer.

* `leaf_not_after_behavior` - (Optional) Behavior of a leaf's NotAfter field during
  issuance.

* `manual_chain` - (Optional) Chain of issuer references to build this issuer's
  computed CAChain field from, when non-empty.

* `usage` - (Optional) Allowed usages for this issuer.

* `revocation_signature_algorithm` - (Optional) Which signature algorithm to use
  when building CRLs.

* `issuing_certificates` - (Optional) Specifies the URL values for the Issuing
  Certificate field.

* `crl_distribution_points` - (Optional) Specifies the URL values for the CRL
  Distribution Points field.

* `delta_crl_distribution_points` - (Optional) Specifies the URL values for the Delta CRL Distribution Points field. Requires Vault 1.20+.

* `ocsp_servers` - (Optional) Specifies the URL values for the OCSP Servers field.

* `enable_aia_url_templating` - (Optional) Specifies that the AIA URL values should
  be templated.

* `disable_critical_extension_checks` - (Optional) This determines whether this
  issuer is able to issue certificates where the chain of trust (including the
  issued certificate) contain critical extensions not processed by Vault.

* `disable_path_length_checks` - (Optional) This determines whether this issuer
  is able to issue certificates where the chain of trust (including the final
  issued certificate) is longer than allowed by a certificate authority in that
  chain.

* `disable_name_checks` - (Optional) This determines whether this issuer is able
  to issue certificates where the chain of trust (including the final issued
  certificate) contains a link in which the subject of the issuing certificate
  does not match the named issuer of the certificate it signed.

* `disable_name_constraint_checks` - (Optional) This determines whether this
  issuer is able to issue certificates where the chain of trust (including the
  final issued certificate) violates the name constraints critical extension of
  one of the issuer certificates in the chain.


## Attributes Reference

The following attributes are exported:

* `issuer_id` - ID of the issuer.

## Import

PKI secret backend issuer can be imported using the `id`, e.g.

```
$ terraform import vault_pki_secret_backend_issuer.example pki/issuer/bf9b0d48-d0dd-652c-30be-77d04fc7e94d
```
