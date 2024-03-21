---
layout: "vault"
page_title: "Vault: vault_identity_oidc_client resource"
sidebar_current: "docs-vault-identity-oidc-client"
description: |-
    Provision OIDC Clients in Vault.
---

# vault\_identity\_oidc\_client

Manages OIDC Clients in a Vault server. See the [Vault documentation](https://www.vaultproject.io/api-docs/secret/identity/oidc-provider#create-or-update-an-assignment)
for more information.

## Example Usage

```hcl
resource "vault_identity_oidc_assignment" "test" {
  name       = "my-assignment"
  entity_ids = ["ascbascas-2231a-sdfaa"]
  group_ids  = ["sajkdsad-32414-sfsada"]
}


resource "vault_identity_oidc_client" "test" {
  name          = "my-app"
  redirect_uris = [
    "http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback",
    "http://127.0.0.1:8251/callback",
    "http://127.0.0.1:8080/callback"
  ]
  assignments = [
    vault_identity_oidc_assignment.test.name
  ]
  id_token_ttl     = 2400
  access_token_ttl = 7200
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required) The name of the client.

* `key` - (Optional) A reference to a named key resource in Vault.
  This cannot be modified after creation. If not provided, the `default`
  key is used.

* `redirect_uris` - (Optional) Redirection URI values used by the client. 
  One of these values must exactly match the `redirect_uri` parameter value
  used in each authentication request.

* `assignments` - (Optional) A list of assignment resources associated with the client.

* `id_token_ttl` - (Optional) The time-to-live for ID tokens obtained by the client. 
  The value should be less than the `verification_ttl` on the key.

* `access_token_ttl` - (Optional) The time-to-live for access tokens obtained by the client.

* `client_type` - (Optional) The client type based on its ability to maintain confidentiality of credentials.
  The following client types are supported: `confidential`, `public`. Defaults to `confidential`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `client_id` - The Client ID returned by Vault.

* `client_secret` - The Client Secret Key returned by Vault.
   For public OpenID Clients `client_secret` is set to an empty string `""`

## Import

OIDC Clients can be imported using the `name`, e.g.

```
$ terraform import vault_identity_oidc_client.test my-app
```
