---
layout: "vault"
page_title: "Vault: vault_pki_resource resource"
sidebar_current: "docs-vault-resource-pki-role"
description: |-
  Configures issuing policies for Vault as a Certificate Authority
---

# vault\_pki\_role

Configures and manages a role in the [Vault PKI secret backend](https://www.vaultproject.io/docs/secrets/pki/index.html).

## Example Usage

```hcl

resource "vault_backend" "pki" {
    path = "pki"
    type = "pki"
}

resource "vault_pki_role" "database_server" {
    backend            = "${vault_backend.pki.path}"
    role               = "database-server"
    ttl                = "600"
    max_ttl            = "900"
    allow_localhost    = false
    allow_domains      = "*.databases.example.org"
    allow_glob_domains = true
    server_flag        = true
    client_flag        = false
    key_type           = "rsa"
    key_bits           = 2048
}
```

## Argument Reference

The following arguments are supported:

* `role` - (Required) Name of the role to configure

* `ttl` - (Optional) Default TTL of the issued certificate

* `max_ttl` - (Optional) Maximum TTL of the issued certificate

* `allow_localhost` - (Optional) Permit issuing certificates for `localhost`

* `allowed_domains` - (Optional) Domains the role can issue certificates for

* `allow_bare_domains` - (Optional) Specifies if client can issue a certificate for the allowed domain directly

* `allow_subdomains` - (Optional) Specifies if a client can issue a certificate for subdomains of the `allowed_domains`

* `allow_glob_domains` - (Optional) Specifies if the `allowed_domains` should be treated as a glob expression

* `allow_any_name` - (Optional) Specifies if the client can request any CN for the certificate

* `enforce_hostnames` - (Optional) Specifies if the CN and DNS SANs are validated as proper hostnames

* `allow_ip_sans` - (Optional) Specifies if the client is able to request IP SANs on the certificate

* `server_flag` - (Optional) Specifies if the certificates issued are valid for server authentication

* `client_flag` - (Optional) Specifies if the certificates issued are valid for client authentication

* `code_signing_flag` - (Optional) Specifies if the certificates issued are valid for code signing

* `email_protection_flag` - (Optional) Specifies if the certificates issued are valid for email authentication and encryption

* `key_type` - (Optional) Specifies the encryption algorithm used to generate the private key

* `key_bits` - (Optional) Specifies the number of bits to used when generating the private key

* `key_usage` - (Optional) Specifies the allowed key usage constraints on the certificate

* `ou` - (Optional) Specifies the OU (Organizational Unit) values in subject of the issued certificate

* `organization` - (Optional) Specifies the O (Organization) values in the subject of the issued certificate

* `generate_lease` - (Optional) Specifies if the certificate issued/signed against this role will have leases attached to them.

* `no_store` - (Optional) Specifies whether or not Vault will store certificates issued against this role in the backend.

* `backend` - (Optional) Path to the mounted PKI secret backend

For more details on the usage of each argument consult the [Vault PKI API documentation](https://www.vaultproject.io/api/secret/pki/index.html).

## Attributes Reference

No additional attributes are exported by this resource.
