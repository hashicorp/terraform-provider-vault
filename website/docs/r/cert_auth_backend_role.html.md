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

* `required_exwtensions` - (Optional) TLS extensions required on client certificates

* `ttl` - (Optional) Default TTL of tokens issued by the backend

* `max_ttl` - (Optional) Maximum TTL of tokens issued by the backend

* `period` - (Optional) Duration in seconds for token.  If set, the issued token is a periodic token.

* `policies` - (Optional) Policies to grant on the issued token

* `display_name` - (Optional) The name to display on tokens issued under this role.

* `backend` - (Optional) Path to the mounted Cert auth backend

For more details on the usage of each argument consult the [Vault Cert API documentation](https://www.vaultproject.io/api/auth/cert/index.html).

## Attribute Reference

No additional attributes are exposed by this resource.
