---
layout: "vault"
page_title: "Vault: pki_secret_backend_root_sign_intermediate resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-root-sign-intermediate"
description: |-
  Signs intermediate certificate.
---

# vault\_pki\_secret\_backend\_root\_sign\_intermediate

Creates PKI certificate.

## Example Usage

```hcl
resource "vault_pki_secret_backend_root_sign_intermediate" "root" {
  depends_on           = [vault_pki_secret_backend_intermediate_cert_request.intermediate]
  backend              = vault_mount.root.path
  csr                  = vault_pki_secret_backend_intermediate_cert_request.intermediate.csr
  common_name          = "Intermediate CA"
  exclude_cn_from_sans = true
  ou                   = "My OU"
  organization         = "My organization"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Required) The PKI secret backend the resource belongs to.

* `csr` - (Required) The CSR

* `common_name` - (Required) CN of intermediate to create

* `alt_names` - (Optional) List of alternative names

* `ip_sans` - (Optional) List of alternative IPs

* `uri_sans` - (Optional) List of alternative URIs

* `other_sans` - (Optional) List of other SANs

* `ttl` - (Optional) Time to live

* `format` - (Optional) The format of data

* `max_path_length` - (Optional) The maximum path length to encode in the generated certificate

* `exclude_cn_from_sans` - (Optional) Flag to exclude CN from SANs

* `use_csr_values` - (Optional) Preserve CSR values

* `permitted_dns_domains` - (Optional) List of domains for which certificates are allowed to be issued

* `ou` - (Optional) The organization unit

* `organization` - (Optional) The organization

* `country` - (Optional) The country

* `locality` - (Optional) The locality

* `province` - (Optional) The province

* `street_address` - (Optional) The street address

* `postal_code` - (Optional) The postal code

* `revoke` - If set to `true`, the certificate will be revoked on resource destruction.

* `issuer_ref` - (Optional) Specifies the default issuer of this request. May
  be the value `default`, a name, or an issuer ID. Use ACLs to prevent access to
  the `/pki/issuer/:issuer_ref/{issue,sign}/:name` paths to prevent users
  overriding the role's `issuer_ref` value.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `certificate` - The intermediate CA certificate in the `format` specified.

* `issuing_ca` - The issuing CA certificate in the `format` specified.

* `ca_chain` - A list of the issuing and intermediate CA certificates in the `format` specified.

* `certificate_bundle` - The concatenation of the intermediate CA and the issuing CA certificates (PEM encoded). 
  Requires the `format` to be set to any of: pem, pem_bundle. The value will be empty for all other formats.
 
* `serial_number` - The certificate's serial number, hex formatted.

