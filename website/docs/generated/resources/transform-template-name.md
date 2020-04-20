---
layout: "vault"
page_title: "Vault: <TODO>"
sidebar_current: "<TODO>"
description: |-
  <TODO>
---

# <TODO>

<TODO>

## Example Usage

<TODO - this and HCL example below>
```hcl
resource "vault_jwt_auth_backend" "example" {
    description  = "Demonstration of the Terraform JWT auth backend"
    path = "jwt"
    oidc_discovery_url = "https://myco.auth0.com/"
    bound_issuer = "https://myco.auth0.com/"
}
```

## Argument Reference

The following arguments are supported:
* `path` - (Required) Path to where the back-end is mounted within Vault.
* `alphabet` - (Optional) The alphabet to use for this template. This is only used during FPE transformations.
* `name` - (Required) The name of the template.
* `pattern` - (Optional) The pattern used for matching. Currently, only regular expression pattern is supported.
* `type` - (Optional) The pattern type to use for match detection. Currently, only regex is supported.
