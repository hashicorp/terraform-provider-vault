---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_config_urls resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-config-urls"
description: |-
  Sets the config URL's on an PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_config\_urls

Allows setting the issuing certificate endpoints, CRL distribution points, and OCSP server endpoints that will be encoded into issued certificates.

## Example Usage

```hcl
resource "vault_mount" "root" {
  path                      = "pki-root"
  type                      = "pki"
  description               = "root PKI"
  default_lease_ttl_seconds = 8640000
  max_lease_ttl_seconds     = 8640000
}

resource "vault_pki_secret_backend_config_urls" "example" {
  backend = vault_mount.root.path
  issuing_certificates = [
    "http://127.0.0.1:8200/v1/pki/ca",
  ]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Required) The path the PKI secret backend is mounted at, with no leading or trailing `/`s.

* `issuing_certificates` - (Optional) Specifies the URL values for the Issuing Certificate field.

* `crl_distribution_points` - (Optional) Specifies the URL values for the CRL Distribution Points field.

* `ocsp_servers` - (Optional) Specifies the URL values for the OCSP Servers field.

* `enable_templating` - (Optional) Specifies that templating of AIA fields is allowed.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

The PKI config URLs can be imported using the resource's `id`. 
In the case of the example above the `id` would be `pki-root/config/urls`, 
where the `pki-root` component is the resource's `backend`, e.g.

```
$ terraform import vault_pki_secret_backend_config_urls.example pki-root/config/urls
```
