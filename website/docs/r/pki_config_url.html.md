---
layout: "vault"
page_title: "Vault: vault_pki_config_url resource"
sidebar_current: "docs-vault-resource-pki-config-url"
description: |-
  Configures the issuing certificate endpoints
---

# vault\_pki\_config\_url

Configures the issuing certificate endpoints.

## Example Usage

```hcl
resource "vault_pki_config_urls" "example-ca-urls" {
  backend = "pki"
  issuing_certificates = [
    "https://127.0.0.1:8200/v1/pki/ca"
  ],
  crl_distribution_points = [
    "https://127.0.0.1:8200/v1/pki/crl"
  ],
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Optional) Name of the pki backend to configure. Defaults to `pki`

* `issuing_certificates` - (Optional) Specifies the URL values for the Issuing Certificate field. 

* `crl_distribution_points` - (Optional) Specifies the URL values for the CRL Distribution Points field.

* `ocsp_servers` - (Optional) Specifies the URL values for the OCSP Servers field.

## Attributes Reference

No additional attributes are exported by this resource.
