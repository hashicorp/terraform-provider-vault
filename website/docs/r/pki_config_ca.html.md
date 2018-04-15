---
layout: "vault"
page_title: "Vault: vault_pki_config_ca resource"
sidebar_current: "docs-vault-resource-pki-config-ca"
description: |-
  Configures a CA ceritifcate and key for a pki backend in Vault
---

# vault\_pki\_config\_ca

Configures a CA ceritifcate and key for a pki backend in Vault.

## Example Usage

```hcl
resource "vault_pki_config_ca" "example-ca-config" {
  backend = "pki"
  cert = <<EOT
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
EOT
  key = <<EOT
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
EOT
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Optional) Name of the pki backend to configure. Defaults to `pki`

* `cert` - (Required) The pem encoded certificate of the CA.

* `key` - (Required) The pem encoded key of the CA. The raw key is not stored in the
  terraform state, instead the sha256 of it is saved.

## Attributes Reference

No additional attributes are exported by this resource.
