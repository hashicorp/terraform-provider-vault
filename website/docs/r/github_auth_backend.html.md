---
layout: "vault"
page_title: "Vault: vault_github_auth_backend resource"
sidebar_current: "docs-vault-github-auth-backend"
description: |-
  Manages Github Auth mounts in Vault.
---

# vault\_github\_auth\_backend

Manages a Github Auth mount in a Vault server. See the [Vault 
documentation](https://www.vaultproject.io/docs/auth/github.html) for more
information.

## Example Usage

```hcl
resource "vault_github_auth_backend" "example" {
  organization = "myorg"
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Optional) Path where the auth backend is mounted. Defaults to `auth/github` 
  if not specified.

* `organization` - (Required) The organization configured users must be part of.

* `base_url` - (Optional) The API endpoint to use. Useful if you 
  are running GitHub Enterprise or an API-compatible authentication server.

* `description` - (Optional) Specifies the description of the mount. 
  This overrides the current stored value, if any.

* `ttl` - (Optional) Duration after which authentication will be expired. 
  This must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration).

* `max_ttl` - (Optional) Maximum duration after which authentication will be expired.
  This must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration).

The `tune` block is used to tune the auth backend:

* `default_lease_ttl` - (Optional) Specifies the default time-to-live. 
  If set, this overrides the global default. 
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `max_lease_ttl` - (Optional) Specifies the maximum time-to-live. 
  If set, this overrides the global default.
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `audit_non_hmac_response_keys` - (Optional) Specifies the list of keys that will 
  not be HMAC'd by audit devices in the response data object.

* `audit_non_hmac_request_keys` - (Optional) Specifies the list of keys that will 
  not be HMAC'd by audit devices in the request data object.

* `listing_visibility` - (Optional) Specifies whether to show this mount in 
  the UI-specific listing endpoint. Valid values are "unauth" or "hidden".

* `passthrough_request_headers` - (Optional) List of headers to whitelist and 
  pass from the request to the backend.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Github authentication mounts can be imported using the `path`, e.g.

```
$ terraform import vault_github_auth_backend_role.example auth/github
```
