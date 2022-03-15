---
layout: "vault"
page_title: "Vault: vault_identity_oidc_provider resource"
sidebar_current: "docs-vault-identity-oidc-provider"
description: |-
    Provision OIDC Providers in Vault.
---

# vault\_identity\_oidc\_provider

Manages OIDC Providers in a Vault server. See the [Vault documentation](https://www.vaultproject.io/api-docs/secret/identity/oidc-provider#create-or-update-an-assignment)
for more information.

## Example Usage

```hcl
resource "vault_identity_oidc_key" "test" {
  name               = "default"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_assignment" "test" {
  name       = "my-assignment"
  entity_ids = ["fake-ascbascas-2231a-sdfaa"]
  group_ids  = ["fake-sajkdsad-32414-sfsada"]
}

resource "vault_identity_oidc_client" "test" {
  name          = "application"
  key           = vault_identity_oidc_key.test.name
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

resource "vault_identity_oidc_scope" "test" {
  name        = "groups"
  template    = "{\"groups\": {{identity.entity.groups.names}} }"
  description = "Groups scope."
}

resource "vault_identity_oidc_provider" "test" {
  name = "my-provider"
  allowed_client_ids = [
    vault_identity_oidc_client.test.client_id
  ]
  scopes_supported = [
    vault_identity_oidc_scope.test.name
  ]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the provider.

* `issuer` - (Required) Specifies what will be used as the `scheme://host:port`
  component for the `iss` claim of ID tokens. If provided explicitly, it must 
  point to a Vault instance that is network reachable by clients for ID token validation.

* `allowed_client_ids` - (Optional) The client IDs that are permitted to use the provider. 
  If empty, no clients are allowed. If `*`, all clients are allowed.

* `scopes_supported` - (Optional) The scopes available for requesting on the provider.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

OIDC Providers can be imported using the `name`, e.g.

```
$ terraform import vault_identity_oidc_provider.test my-provider
```

