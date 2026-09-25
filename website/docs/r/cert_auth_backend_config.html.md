---
layout: "vault"
page_title: "Vault: cert_auth_backend_config resource"
sidebar_current: "docs-vault-resource-cert-auth-backend-config"
description: |-
  Configures the certificate auth backend
---

# vault\_cert\_auth\_backend\_config

Provides configuration for [Cert auth backend within Vault](https://www.vaultproject.io/docs/auth/cert.html).

## Example Usage

```hcl
resource "vault_auth_backend" "cert" {
  type = "cert"
  path = "cert"
}

resource "vault_cert_auth_backend_config" "config" {
  disable_binding = false
  enable_identity_alias_metadata = true"
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `disable_binding` - (Optional) If set, during renewal, skips the matching of 
  presented client identity with the client identity used during login.

* `enable_identity_alias_metadata` - (Optional) If set, metadata of the certificate including 
  the metadata corresponding to allowed_metadata_extensions will be stored in the alias.

* `backend` - (Optional) Path to the mounted Cert auth backend

For more details on the usage of each argument consult the [Vault Cert API documentation](https://www.vaultproject.io/api-docs/auth/cert).

## Attribute Reference

No additional attributes are exposed by this resource.
