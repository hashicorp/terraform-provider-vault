---
layout: "vault"
page_title: "Vault: vault_pki_role resource"
sidebar_current: "docs-vault-resource-pki-role"
description: |-
  Writes and updates pki role definitions
---

# vault\_pki\_role

Writes and updates pki role definitions.

## Example Usage

```hcl
resource "vault_pki_role" "example-ca-role" {
  backend = "pki"
  name = "example-ca-role"
  allowed_domains = [
    "example.com"
  ]
  allow_subdomains = true
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Optional) Name of the pki backend. Defaults to `pki`

* `name` - (Required) Specifies the name of the role to create

* `ttl` - (Optional) Specifics the Time To Live value provided as a string duration with time suffix. Hour is the largest suffix.

* `max_ttl` - (Optional) Specifies the maximum Time To Live provided as a string duration with time suffix. Hour is the largest suffix.

* `allow_localhost` - (Optional) Specifies if clients can request certificates for localhost as one of the requested common names. Defaults to `true`

* `allowed_domains` - (Optional) Specifies the domains of the role. This is used with the allow_bare_domains and allow_subdomains options.

* `allow_bare_domains` - (Optional) Specifies if clients can request certificates matching the value of the actual domains themselves. Defaults to `false`

* `allow_subdomains` - (Optional) Specifies if clients can request certificates with CNs that are subdomains of the CNs allowed by the other role options. Defaults to `false`

* `allow_glob_domains` - (Optional) Allows names specified in allowed_domains to contain glob patterns. Defaults to `false`

* `allow_any_name` - (Optional) Specifies if clients can request any CN. Defaults to `false`

* `enforce_hostnames` - (Optional) Specifies if only valid host names are allowed for CNs, DNS SANs, and the host part of email addresses. Defaults to `true`

* `allow_ip_sans` - (Optional) Specifies if clients can request IP Subject Alternative Names. Defaults to `true`

* `allow_other_sans` - (Optional) Defines allowed custom OID/UTF8-string SANs.

* `server_flag` - (Optional) Specifies if certificates are flagged for server use. Defaults to `true`

* `client_flag` - (Optional) Specifies if certificates are flagged for client use. Defaults to `true`

* `code_signing_flag` - (Optional) Specifies if certificates are flagged for code signing use. Defaults to `false`

* `email_protection_flag` - (Optional) Specifies if certificates are flagged for email protection use. Defalse to `false`

* `key_type` - (Optional) Specifies the type of key to generate for generated private keys. Defaults to `rsa`

* `key_usage` - (Optional) Specifies the allowed key usage constraint on issued certificates.

* `use_csr_common_name` - (Optional) When used with the CSR signing endpoint, the common name in the CSR will be used instead of taken from the JSON data. Defaults to `true`

* `use_csr_sans` - (Optional) When used with the CSR signing endpoint, the subject alternate names in the CSR will be used instead of taken from the JSON data. Defaults to `true`

* `ou` - (Optional) Specifies the OU (OrganizationalUnit) values in the subject field of issued certificates.

* `organization` - (Optional) Specifies the O (Organization) values in the subject field of issued certificates.

* `country` - (Optional) Specifies the C (Country) values in the subject field of issued certificates.

* `locality` - (Optional) Specifies the L (Locality) values in the subject field of issued certificates.

* `province` - (Optional) Specifies the ST (Province) values in the subject field of issued certificates.

* `street_address` - (Optional) Specifies the Street Address values in the subject field of issued certificates.

* `postal_code` - (Optional) Specifies the Postal Code values in the subject field of issued certificates.

* `generate_lease` - (Optional) Specifies if certificates issued/signed against this role will have Vault leases attached to them. Defaults to `false`

* `no_store` - (Optional) If set, certificates issued/signed against this role will not be stored in the storage backend. Defaults to `false`

* `require_cn` - (Optional) If set to false, makes the common_name field optional while generating a certificate. Defaults to `true`

* `policy_identifiers` - (Optional) A comma-separated string or list of policy oids.

* `basic_constraints_valid_for_non_ca` - (Optional) Mark Basic Constraints valid when issuing non-CA certificates.


## Attributes Reference

No additional attributes are exported by this resource.
