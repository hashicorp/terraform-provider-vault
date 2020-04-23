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
* `allowed_roles` - (Optional) The set of roles allowed to perform this transformation.
* `masking_character` - (Optional) The character used to replace data when in masking mode
* `name` - (Required) The name of the transformation.
* `template` - (Optional) The name of the template to use.
* `tweak_source` - (Optional) The source of where the tweak value comes from. Only valid when in FPE mode.
* `type` - (Optional) The type of transformation to perform.
