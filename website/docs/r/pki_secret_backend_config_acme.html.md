---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_config_acme resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-config-acme"
description: |-
  Sets the ACME configuration on a PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_config\_acme

Allows setting the ACME server configuration used by specified mount.

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path                      = "pki"
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_config_cluster" "pki_config_cluster" {
  backend  = vault_mount.pki.path
  path     = "http://127.0.0.1:8200/v1/pki"
  aia_path = "http://127.0.0.1:8200/v1/pki"
}

resource "vault_pki_secret_backend_config_acme" "example" {
  backend                  = vault_mount.pki.path
  enabled                  = true
  allowed_issuers          = ["*"]
  allowed_roles            = ["*"]
  allow_role_ext_key_usage = false
  default_directory_policy = "sign-verbatim"
  dns_resolver             = ""
  eab_policy               = "not-required"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Required) The path the PKI secret backend is mounted at, with no leading or trailing `/`s.

* `enabled` - (Required) Specifies whether ACME is enabled.

* `allowed_issuers` - (Optional) Specifies which issuers are allowed for use with ACME.

* `allowed_roles` - (Optional) Specifies which roles are allowed for use with ACME.

* `allow_role_ext_key_usage` - (Optional) Specifies whether the ExtKeyUsage field from a role is used. **Vault 1.14.1+**

* `default_directory_policy` - (Optional) Specifies the policy to be used for non-role-qualified ACME requests.
  Allowed values are `forbid`, `sign-verbatim`, `role:<role_name>`, `external-policy` or `external-policy:<policy>`.

* `dns_resolver` - (Optional) DNS resolver to use for domain resolution on this mount.
  Must be in the format `<host>:<port>`, with both parts mandatory.

* `eab_policy` - (Optional) Specifies the policy to use for external account binding behaviour.
  Allowed values are `not-required`, `new-account-required` or `always-required`.

* `max_ttl` - (Optional) The maximum TTL in seconds for certificates issued by ACME. **Vault 1.17.0+**

## Attributes Reference

No additional attributes are exported by this resource.

## Import

The ACME configuration can be imported using the resource's `id`. 
In the case of the example above the `id` would be `pki/config/acme`, 
where the `pki` component is the resource's `backend`, e.g.

```
$ terraform import vault_pki_secret_backend_config_acme.example pki/config/acme
```
