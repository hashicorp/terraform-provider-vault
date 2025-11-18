---
layout: "vault"
page_title: "Vault: vault_spiffe__config resource"
sidebar_current: "docs-vault-resource-vault_spiffe__config"
description: |-
  Update the main configuration of the SPIFFE backend in Vault.
---

# vault\_spiffe\_config

Configure the SPIFFE trust domain.


## Example Usage

```hcl
resource "vault_mount" "spiffe_secrets" {
  path = "spiffe"
  type = "spiffe"
}

resource "vault_spiffe_backend_config" "spiffe_config" {
	mount		 = vault_mount.spiffe_secrets.path
	trust_domain = "example.com"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `mount` - (Required) The PKI secret backend the resource belongs to.

* `trust_domain` - (Required)  The SPIFFE trust domain used by the backend. 

* `bundle_refresh_hint` - (Optional) The value to put as the refresh hint in trust bundles we publish.
May not exceed key_lifetime/10. Uses 
[duration](https://developer.hashicorp.com/vault/docs/concepts/duration-format) format strings.

* `key_lifetime` - (Optional) How often to generate a new signing key. Uses 
[duration](https://developer.hashicorp.com/vault/docs/concepts/duration-format) format strings.

* `jwt_issuer_url` - (Optional) The base URL to use for JWT issuer claims (`iss`), including
  `https://` schema, host, and optional port. Must be reachable by whatever systems consume the JWTs.

* `jwt_signing_algorithm` - (Optional) Signing algorithm to use. Allowed values are: RS256 (default),
  RS384, RS512, ES256, ES384, ES512.
  
* `jwt_oidc_compatibility_mode` - (Optional) When set true, attempts to generate JWT SVIDs will fail if the resulting
  SPIFFEID exceeds 255 chars, the limit for JWT sub claims in OIDC.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

The SPIFFE config can be imported using the resource's `id`.
In the case of the example above the `id` would be `spiffe/config`,
where the `spiffe` component is the resource's `mount`, e.g.

```
$ terraform import vault_spiffe_backend_config.spiffe_config spiffe/config
```
