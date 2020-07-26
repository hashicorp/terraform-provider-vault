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
{{- range .Parameters }}
* `{{ .Name }}` - {{ if .Required }}(Required){{ else }}(Optional){{ end }} {{ .Description }}
{{- end }}
