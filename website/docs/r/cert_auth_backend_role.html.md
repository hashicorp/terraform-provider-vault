---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-cert-auth-backend-role"
description: |-
  Managing roles in an Cert auth backend in Vault
---

# vault\_cert\_auth\_backend\_role

Provides a resource to create a role in an [Cert auth backend within Vault](https://www.vaultproject.io/docs/auth/cert.html).

## Example Usage

```hcl
resource "vault_auth_backend" "cert" {
    path = "cert"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "cert" {
    name          = "foo"
    certificate   = "${file("/path/to/certs/ca-cert.pem")}"
    backend       = "${vault_auth_backend.cert.path}"
    allowed_names = ["foo.example.org", "baz.example.org"]
    ttl           = 300
    max_ttl       = 600
    policies      = ["foo"]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the role

* `certificate` - (Required) CA certificate used to validate client certificates

* `allowed_names` - (Optional) Allowed subject names for authenticated client certificates

* `allowed_common_names` - (Optional) Allowed the common names for authenticated client certificates

* `allowed_dns_sans` - (Optional) Allowed alternative dns names for authenticated client certificates

* `allowed_email_sans` - (Optional) Allowed emails for authenticated client certificates

* `allowed_uri_sans` - (Optional) Allowed URIs for authenticated client certificates

* `allowed_organization_units` - (Optional) Allowed organization units for authenticated client certificates

* `required_extensions` - (Optional) TLS extensions required on client certificates

* `ttl` - (Optional) Default TTL of tokens issued by the backend

* `max_ttl` - (Optional) Maximum TTL of tokens issued by the backend

* `period` - (Optional) Duration in seconds for token.  If set, the issued token is a periodic token.

* `policies` - (Optional) Policies to grant on the issued token

* `display_name` - (Optional) The name to display on tokens issued under this role.

* `bound_cidrs` - (Optional) Restriction usage of the certificates to client IPs falling within the range of the specified CIDRs

* `backend` - (Optional) Path to the mounted Cert auth backend

For more details on the usage of each argument consult the [Vault Cert API documentation](https://www.vaultproject.io/api/auth/cert/index.html).

## Attribute Reference

No additional attributes are exposed by this resource.
