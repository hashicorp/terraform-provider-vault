---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_config_issuers resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-config-issuers"
description: |-
  Allows setting the value of the default issuer.
---

# vault\_pki\_secret\_backend\_config\_issuers

Allows setting the value of the default issuer. For more information, see the
[Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/pki#set-issuers-configuration)

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path                      = "pki"
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_root_cert" "root" {
  backend     = vault_mount.pki.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
}

resource "vault_pki_secret_backend_issuer" "example" {
  backend     = vault_pki_secret_backend_root_cert.root.backend
  issuer_ref  = vault_pki_secret_backend_root_cert.root.issuer_id
  issuer_name = "example-issuer"
}

resource "vault_pki_secret_backend_config_issuers" "config" {
  backend                       = vault_mount.pki.path
  default                       = vault_pki_secret_backend_issuer.example.issuer_id
  default_follows_latest_issuer = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) The path the PKI secret backend is mounted at, with no
  leading or trailing `/`s.

* `default` - (Required) Specifies the default issuer using the issuer ID.
  **NOTE:** It is recommended to only set the default issuer using the ID. 
  While Vault does allow passing in the issuer name, this can lead to possible drifts in the Terraform state.

* `default_follows_latest_issuer` - (Optional) Specifies whether a root creation
  or an issuer import operation updates the default issuer to the newly added issuer.


## Attributes Reference

No additional attributes are exported by this resource.

## Import

PKI secret backend config issuers can be imported using the path, e.g.

```
$ terraform import vault_pki_secret_backend_issuer.config pki/config/issuers
```
