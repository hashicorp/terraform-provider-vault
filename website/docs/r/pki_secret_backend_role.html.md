---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_role resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-role"
description: |-
  Create a role on an PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_role

Creates a role on an PKI Secret Backend for Vault.

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path                      = "pki"
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_role" "role" {
  backend          = vault_mount.pki.path
  name             = "my_role"
  ttl              = 3600
  allow_ip_sans    = true
  key_type         = "rsa"
  key_bits         = 4096
  allowed_domains  = ["example.com", "my.domain"]
  allow_subdomains = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Required) The path the PKI secret backend is mounted at, with no leading or trailing `/`s.

* `name` - (Required) The name to identify this role within the backend. Must be unique within the backend.

* `issuer_ref` - (Optional) Specifies the default issuer of this request. May
  be the value `default`, a name, or an issuer ID. Use ACLs to prevent access to
  the `/pki/issuer/:issuer_ref/{issue,sign}/:name` paths to prevent users
  overriding the role's `issuer_ref` value.

* `ttl` - (Optional, integer) The TTL, in seconds, for any certificate issued against this role.

* `max_ttl` - (Optional, integer) The maximum lease TTL, in seconds, for the role.

* `allow_localhost` - (Optional) Flag to allow certificates for localhost

* `allowed_domains` - (Optional) List of allowed domains for certificates

* `allowed_domains_template` - (Optional) Flag, if set, `allowed_domains` can be specified using identity template expressions such as `{{identity.entity.aliases.<mount accessor>.name}}`.

* `allow_bare_domains` - (Optional) Flag to allow certificates matching the actual domain

* `allow_subdomains` - (Optional) Flag to allow certificates matching subdomains

* `allow_glob_domains` - (Optional) Flag to allow names containing glob patterns.

* `allow_any_name` - (Optional) Flag to allow any name

* `enforce_hostnames` - (Optional) Flag to allow only valid host names

* `allow_ip_sans` - (Optional) Flag to allow IP SANs

* `allowed_uri_sans` - (Optional) Defines allowed URI SANs

* `allowed_user_ids` - (Optional) Defines allowed User IDs

* `allowed_uri_sans_template` - (Optional) Flag, if set, `allowed_uri_sans` can be specified using identity template expressions such as `{{identity.entity.aliases.<mount accessor>.name}}`.

* `allowed_other_sans` - (Optional) Defines allowed custom SANs

* `allow_wildcard_certificates` - (Optional) Flag to allow wildcard certificates.

* `server_flag` - (Optional) Flag to specify certificates for server use

* `client_flag` - (Optional) Flag to specify certificates for client use

* `cn_validations` - (Optional) Validations to run on the Common Name field of the certificate, choices: `email`, `hostname`, `disabled`

* `code_signing_flag` - (Optional) Flag to specify certificates for code signing use

* `email_protection_flag` - (Optional) Flag to specify certificates for email protection use

* `key_type` - (Optional) The generated key type, choices: `rsa`, `ec`, `ed25519`, `any`
  Defaults to `rsa`

* `key_bits` - (Optional) The number of bits of generated keys

* `signature_bits` - (Optional) The number of bits to use in the signature algorithm

* `key_usage` - (Optional) Specify the allowed key usage constraint on issued
  certificates. Defaults to `["DigitalSignature", "KeyAgreement", "KeyEncipherment"])`.
  To specify no default key usage constraints, set this to an empty list `[]`.

* `ext_key_usage` - (Optional) Specify the allowed extended key usage constraint on issued certificates

* `ext_key_usage_oids` - (Optional) Specify the allowed extended key usage OIDs constraint on issued certificates

* `use_csr_common_name` - (Optional) Flag to use the CN in the CSR

* `use_csr_sans` - (Optional) Flag to use the SANs in the CSR

* `ou` - (Optional) The organization unit of generated certificates

* `organization` - (Optional) The organization of generated certificates

* `country` - (Optional) The country of generated certificates

* `locality` - (Optional) The locality of generated certificates

* `province` - (Optional) The province of generated certificates

* `street_address` - (Optional) The street address of generated certificates

* `postal_code` - (Optional) The postal code of generated certificates

* `generate_lease` - (Optional) Flag to generate leases with certificates

* `no_store` - (Optional) Flag to not store certificates in the storage backend

* `require_cn` - (Optional) Flag to force CN usage

* `policy_identifiers` - (Optional) Specify the list of allowed policies OIDs. Use with Vault 1.10 or before. For Vault 1.11+, use `policy_identifier` blocks instead

* `policy_identifier` - (Optional) (Vault 1.11+ only) A block for specifying policy identifers. The `policy_identifier` block can be repeated, and supports the following arguments:

   - `oid` - (Required) The OID for the policy identifier

   - `notice` - (Optional) A notice for the policy identifier

   - `cps` - (Optional) The URL of the CPS for the policy identifier

* `use_pss` - (Optional) Specifies whether or not to use PSS signatures over PKCS#1v1.5 signatures when a RSA-type issuer is used. Ignored for ECDSA/Ed25519 issuers.

* `no_store_metadata` - (Optional) Allows metadata to be stored keyed on the certificate's serial number. The field is independent of no_store, allowing metadata storage regardless of whether certificates are stored. If true, metadata is not stored and an error is returned if the metadata field is specified on issuance APIs

* `serial_number_source` - (Optional) Specifies the source of the subject serial number. Valid values are json-csr (default) or json. When set to json-csr, the subject serial number is taken from the serial_number parameter and falls back to the serial number in the CSR. When set to json, the subject serial number is taken from the serial_number parameter but will ignore any value in the CSR. For backwards compatibility an empty value for this field will default to the json-csr behavior.

   Example usage:
```hcl
resource "vault_mount" "pki" {
  path                      = "pki"
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_role" "role" {
  backend          = vault_mount.pki.path
  name             = "my_role"
  ttl              = 3600
  allow_ip_sans    = true
  key_type         = "rsa"
  key_bits         = 4096
  allowed_domains  = ["example.com", "my.domain"]
  allow_subdomains = true

  policy_identifier {
    oid = "1.3.6.1.4.1.7.8"
    notice= "I am a user Notice"
  }
  policy_identifier {
    oid = "1.3.6.1.4.1.32473.1.2.4"
    cps = "https://example.com"
  }
}
```



* `basic_constraints_valid_for_non_ca` - (Optional) Flag to mark basic constraints valid when issuing non-CA certificates

* `not_before_duration` - (Optional) Specifies the [duration](https://developer.hashicorp.com/vault/docs/concepts/duration-format) by which to backdate the NotBefore property.

* `allowed_serial_numbers` - (Optional) An array of allowed serial numbers to put in Subject

* `not_after` - (Optional) Set the Not After field of the certificate with specified date value. The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ. Supports the Y10K end date for IEEE 802.1AR-2018 standard devices, 9999-12-31T23:59:59Z.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

PKI secret backend roles can be imported using the `path`, e.g.

```
$ terraform import vault_pki_secret_backend_role.role pki/roles/my_role
```
