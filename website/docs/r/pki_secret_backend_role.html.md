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
resource "vault_pki_secret_backend" "pki" {
  path                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_role" "role" {
  backend          = vault_pki_secret_backend.pki.path
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

* `backend` - (Required) The path the PKI secret backend is mounted at, with no leading or trailing `/`s.

* `name` - (Required) The name to identify this role within the backend. Must be unique within the backend.

* `ttl` - (Optional) The TTL

* `max_ttl` - (Optional) The maximum TTL

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

* `allowed_other_sans` - (Optional) Defines allowed custom SANs

* `server_flag` - (Optional) Flag to specify certificates for server use

* `client_flag` - (Optional) Flag to specify certificates for client use

* `code_signing_flag` - (Optional) Flag to specify certificates for code signing use

* `email_protection_flag` - (Optional) Flag to specify certificates for email protection use

* `key_type` - (Optional) The type of generated keys

* `key_bits` - (Optional) The number of bits of generated keys

* `key_usage` - (Optional) Specify the allowed key usage constraint on issued certificates

* `ext_key_usage` - (Optional) Specify the allowed extended key usage constraint on issued certificates

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

* `policy_identifiers` - (Optional) Specify the list of allowed policies IODs

* `basic_constraints_valid_for_non_ca` - (Optional) Flag to mark basic constraints valid when issuing non-CA certificates

* `not_before_duration` - (Optional) Specifies the duration by which to backdate the NotBefore property.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

PKI secret backend roles can be imported using the `path`, e.g.

```
$ terraform import vault_pki_secret_backend_role.role pki/roles/my_role
```
