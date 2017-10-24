---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-okta-auth-backend"
description: |-
  Managing Okta auth backends in Vault
---

# vault\_okta\_auth\_backend

Provides a resource for managing an
[Okta auth backend within Vault](https://www.vaultproject.io/docs/auth/okta.html).

## Example Usage

```hcl
resource "vault_okta_auth_backend" "example" {
    description = "Demonstration of the Terraform Okta auth backend"
    organization = "example"
    token = "something that should be kept secret"
    group {
        group_name = "foo"
        policies = ["one", "two"]
    }
    user {
        username = "bar"
        groups = ["foo"]
    }
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) Path to mount the Okta auth backend

* `description` - (Optional) The description of the auth backend

* `organization` - (Required) The Okta organization. This will be the first part of the url `https://XXX.okta.com`

* `token` - (Optional) The Okta API token. This is required to query Okta for user group membership.
If this is not supplied only locally configured groups will be enabled.

* `base_url` - (Optional) The Okta url. Examples: oktapreview.com, okta.com

* `ttl` - (Optional) Duration after which authentication will be expired.
[See the documentation for info on valid duration formats](https://golang.org/pkg/time/#ParseDuration).

* `max_ttl` - (Optional) Maximum duration after which authentication will be expired
[See the documentation for info on valid duration formats](https://golang.org/pkg/time/#ParseDuration).

* `group` - (Optional) Associate Okta groups with policies within Vault.
[See below for more details](#okta-group). 

* `user` - (Optional) Associate Okta users with groups or policies within Vault.
[See below for more details](#okta-user). 

### Okta Group

* `group_name` - (Required) Name of the group within the Okta

* `policies` - (Optional) Vault policies to associate with this group

### Okta User

* `username` - (Required Optional) Name of the user within Okta

* `groups` - (Optional) List of Okta groups to associate with this user

* `policies` - (Optional) List of Vault policies to associate with this user

## Attributes Reference

No additional attributes are exposed by this resource.
