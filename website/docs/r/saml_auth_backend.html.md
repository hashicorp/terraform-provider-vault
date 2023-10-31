---
layout: "vault"
page_title: "Vault: vault_saml_auth_backend resource"
sidebar_current: "docs-vault-saml-auth-backend"
description: |-
Manages SAML Auth mounts in Vault.
---

# vault\_saml\_auth\_backend

Manages a SAML Auth mount in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/saml/) for more
information.

## Example Usage

```hcl
resource "vault_saml_auth_backend" "test" {
  path             = "saml"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback"]
  default_role     = "admin"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Optional) Path where the auth backend will be mounted. Defaults to `auth/saml`
  if not specified.

* `disable_remount` - (Optional) If set to `true`, opts out of mount migration on path updates.
  See here for more info on [Mount Migration](https://www.vaultproject.io/docs/concepts/mount-migration)

* `idp_metadata_url` - (Optional) The metadata URL of the identity provider.

* `idp_sso_url` (Optional) The SSO URL of the identity provider. Mutually exclusive with 
  `idp_metadata_url`.

* `idp_entity_id` (Optional) The entity ID of the identity provider. Mutually exclusive with
  `idp_metadata_url`.

* `idp_cert` (Optional) The PEM encoded certificate of the identity provider. Mutually exclusive
  with `idp_metadata_url`.

* `entity_id` - (Optional) The entity ID of the SAML authentication service provider.

* `acs_urls` - (Optional) The well-formatted URLs of your Assertion Consumer Service (ACS)
  that should receive a response from the identity provider.

* `default_role` - (Optional) The role to use if no role is provided during login.

* `verbose_logging` - (Optional) If set to `true`, logs additional, potentially sensitive
  information during the SAML exchange according to the current logging level. Not 
  recommended for production.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

SAML authentication mounts can be imported using the `path`, e.g.

```
$ terraform import vault_saml_auth_backend.example saml
```
