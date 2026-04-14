---
layout: "vault"
page_title: "Vault: vault_sys_config_cors data source"
sidebar_current: "docs-vault-datasource-sys-config-cors"
description: |-
  Reads the current CORS configuration from Vault
---

# vault\_sys\_config\_cors

Reads the current CORS (Cross-Origin Resource Sharing) configuration from Vault.

~> **Important** This data source reads from the root namespace only.

**Note** This feature is available in Vault 1.14+

## Example Usage

```hcl
data "vault_sys_config_cors" "current" {}

output "cors_enabled" {
  value = data.vault_sys_config_cors.current.enabled
}

output "allowed_origins" {
  value = data.vault_sys_config_cors.current.allowed_origins
}

output "allowed_headers" {
  value = data.vault_sys_config_cors.current.allowed_headers
}
```

### Using with resource

```hcl
resource "vault_sys_config_cors" "production" {
  allowed_origins = [
    "https://app.example.com",
    "https://admin.example.com",
    "https://api.example.com"
  ]
  
  allowed_headers = [
    "X-Custom-Header",
    "X-Request-ID",
    "X-Application-Version"
  ]
}

data "vault_sys_config_cors" "current" {
  depends_on = [vault_sys_config_cors.production]
}

output "cors_configuration" {
  value = {
    enabled         = data.vault_sys_config_cors.current.enabled
    allowed_origins = data.vault_sys_config_cors.current.allowed_origins
    allowed_headers = data.vault_sys_config_cors.current.allowed_headers
  }
}
```

## Argument Reference

This data source has no arguments.

## Attributes Reference

The following attributes are exported:

* `enabled` - Whether CORS is currently enabled.

* `allowed_origins` - Set of origins permitted to make cross-origin requests. Returns an empty set if CORS is disabled.

* `allowed_headers` - Set of additional custom headers allowed on cross-origin requests. Returns an empty set if CORS is disabled or no custom headers are configured. This only includes custom headers that were explicitly configured, not the standard Vault headers (Content-Type, X-Requested-With, X-Vault-AWS-IAM-Server-ID, X-Vault-MFA, X-Vault-No-Request-Forwarding, X-Vault-Wrap-Format, X-Vault-Wrap-TTL, X-Vault-Policy-Override, Authorization, X-Vault-Token) that are automatically included when CORS is enabled.

## API Documentation

For more information on the Vault CORS configuration API, see the [Vault API documentation](https://developer.hashicorp.com/vault/api-docs/system/config-cors).