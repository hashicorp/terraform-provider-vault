---
layout: "vault"
page_title: "Vault: vault_pki_external_ca_secret_backend_role resource"
sidebar_current: "docs-vault-resource-pki-external-ca-secret-backend-role"
description: |-
  Manages PKI External CA roles for certificate issuance via ACME.
---

# vault\_pki\_external\_ca\_secret\_backend\_role

Manages PKI External CA roles for certificate issuance via ACME. This resource defines the configuration for obtaining certificates from external Certificate Authorities through the ACME protocol.

## Example Usage

```hcl
resource "vault_mount" "pki-external-ca" {
  path = "pki-external-ca"
  type = "pki-external-ca"
}

resource "vault_pki_external_ca_secret_backend_acme_account" "example" {
  mount         = vault_mount.pki-external-ca.path
  name          = "my-acme-account"
  directory_url = "https://acme-v02.api.letsencrypt.org/directory"
  email_contacts = [
    "admin@example.com"
  ]
}

resource "vault_pki_external_ca_secret_backend_role" "example" {
  mount            = vault_mount.pki-external-ca.path
  name             = "example-role"
  acme_account_name = vault_pki_external_ca_secret_backend_acme_account.example.name
  
  allowed_domains = [
    "example.com",
    "*.example.com"
  ]
  
  allowed_domain_options = [
    "bare_domains",
    "subdomains",
    "wildcards"
  ]
  
  allowed_challenge_types = [
    "http-01",
    "dns-01"
  ]
}
```

## Example Usage with Identity Templates

```hcl
resource "vault_pki_external_ca_secret_backend_role" "templated" {
  mount             = vault_mount.pki-external-ca.path
  name              = "user-role"
  acme_account_name = vault_pki_external_ca_secret_backend_acme_account.example.name
  
  allowed_domains = [
    "{{identity.entity.aliases.auth_userpass_xxxxx.name}}.example.com"
  ]
  
  allowed_domain_options = [
    "bare_domains"
  ]
  
  csr_generate_key_type      = "rsa-2048"
  csr_identifier_population  = "cn_first"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `mount` - (Required) The path where the PKI External CA secret backend is mounted.

* `name` - (Required) Name of the role. Must be unique within the backend.

* `acme_account_name` - (Required) The ACME account to use when validating certificates.

* `allowed_domains` - (Optional) A list of domains the role will accept certificates for. May contain templates, as with ACL Path Templating (e.g., `{{identity.entity.aliases.<mount accessor>.name}}`).

* `allowed_domain_options` - (Optional) A list of keyword options that influence how values within `allowed_domains` are interpreted against the requested set of identifiers from the client. Valid values are:
  - `bare_domains` - Allow exact domain matches
  - `subdomains` - Allow subdomains of the specified domains
  - `wildcards` - Allow wildcard certificates
  - `globs` - Allow glob patterns in domain names
  
  Defaults to an empty list.

* `allowed_challenge_types` - (Optional) The list of challenge types that are allowed to be used. Valid values are `http-01`, `dns-01`, `tls-alpn-01`. Defaults to all challenge types.

* `csr_generate_key_type` - (Optional) The key type and size/parameters to use when generating a new key if running in the identifier workflow. Valid values are `ec-256`, `ec-384`, `ec-521`, `rsa-2048`, `rsa-4096`. Defaults to `ec-256`.

* `csr_identifier_population` - (Optional) The technique used to populate a CSR from the provided identifiers in the identifier workflow. Valid values are:
  - `cn_first` - Use the first identifier as the Common Name and all identifiers as SANs
  - `sans_only` - Use all identifiers as SANs only (no CN)
  
  Defaults to `cn_first`.

* `force` - (Optional) Force deletion even when active orders exist. Defaults to `false`.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `id` - The ID of the resource in the format `<mount>/role/<name>`.

* `creation_date` - The date and time the role was created in RFC3339 format.

* `last_update_date` - The date and time the role was last updated in RFC3339 format.

## Import

PKI External CA roles can be imported using the format `<mount>/role/<name>`, e.g.

```
$ terraform import vault_pki_external_ca_secret_backend_role.example pki-external-ca/role/example-role