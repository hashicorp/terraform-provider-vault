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
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
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

* `key_usage` - (Optional) Specify the key usages to be added to the existing set of key usages ("CRL", "CertSign") on the generated certificate. Requires Vault 1.19.2+.

* `exclude_cn_from_sans` - (Optional) Flag to exclude CN from SANs

* `use_csr_values` - (Optional) Preserve CSR values

* `permitted_dns_domains` - (Optional) List of domains for which certificates are allowed to be issued

* `excluded_dns_domains` - (Optional) List of domains for which certificates are not allowed to be issued. Requires Vault version 1.19+.

* `permitted_ip_ranges` - (Optional)  List of IP ranges for which certificates are allowed to be issued. Requires Vault version 1.19+.

* `excluded_ip_ranges` - (Optional) List of IP ranges for which certificates are not allowed to be issued. Requires Vault version 1.19+.

* `permitted_email_addresses` - (Optional) List of email addresses for which certificates are allowed to be issued. Requires Vault version 1.19+.

* `excluded_email_addresses` - (Optional) List of email addresses for which certificates are not allowed to be issued. Requires Vault version 1.19+.

* `permitted_uri_domains` - (Optional) List of URI domains for which certificates are allowed to be issued. Requires Vault version 1.19+.

* `excluded_uri_domains` - (Optional) List of URI domains for which certificates are not allowed to be issued. Requires Vault version 1.19+.

* `ou` - (Optional) The organization unit

* `organization` - (Optional) The organization

* `country` - (Optional) The country

* `locality` - (Optional) The locality

* `province` - (Optional) The province

* `street_address` - (Optional) The street address

* `postal_code` - (Optional) The postal code

* `signature_bits` - (Optional) The number of bits to use in the signature algorithm

* `skid` - (Optional) Value for the Subject Key Identifier field (see https://tools.ietf.org/html/rfc5280#section-4.2.1.2). Specified as a string in hex format.

* `use_pss` - (Optional) Specifies whether or not to use PSS signatures over PKCS#1v1.5 signatures when a RSA-type issuer is used. Ignored for ECDSA/Ed25519 issuers.

* `revoke` - If set to `true`, the certificate will be revoked on resource destruction.

* `issuer_ref` - (Optional) Specifies the default issuer of this request. May
  be the value `default`, a name, or an issuer ID. Use ACLs to prevent access to
  the `/pki/issuer/:issuer_ref/{issue,sign}/:name` paths to prevent users
  overriding the role's `issuer_ref` value.

* `not_after` - (Optional) Set the Not After field of the certificate with specified date value. 
The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ. Supports the Y10K end date 
for IEEE 802.1AR-2018 standard devices, 9999-12-31T23:59:59Z.

* `not_before_duration` - (Optional) Specifies the [duration](https://developer.hashicorp.com/vault/docs/concepts/duration-format) by which to backdate the NotBefore property.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `certificate` - The intermediate CA certificate in the `format` specified.

* `issuing_ca` - The issuing CA certificate in the `format` specified.

* `ca_chain` - A list of the issuing and intermediate CA certificates in the `format` specified.

* `certificate_bundle` - The concatenation of the intermediate CA and the issuing CA certificates (PEM encoded). 
  Requires the `format` to be set to any of: pem, pem_bundle. The value will be empty for all other formats.
 
* `serial_number` - The certificate's serial number, hex formatted.
