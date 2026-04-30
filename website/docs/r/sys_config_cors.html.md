---
layout: "vault"
page_title: "Vault: vault_sys_config_cors resource"
sidebar_current: "docs-vault-resource-sys-config-cors"
description: |-
  Manages CORS configuration for Vault
---

# vault\_sys\_config\_cors

Manages the CORS (Cross-Origin Resource Sharing) configuration for Vault, controlling which origins can make cross-origin requests and which headers are allowed.

~> **Important** This resource requires `sudo` capability and must be called from the root namespace. CORS configuration does not replicate across Performance Replication clusters in Vault Enterprise.

**Note** This feature is available in Vault 1.14+

## Example Usage

### Enable CORS for specific origins

```hcl
resource "vault_sys_config_cors" "example" {
  allowed_origins = [
    "http://www.example.com",
    "https://app.example.com"
  ]
  
  allowed_headers = [
    "X-Custom-Header",
    "X-Application-ID"
  ]
}
```

### Allow all origins (wildcard)

```hcl
resource "vault_sys_config_cors" "wildcard" {
  allowed_origins = ["*"]
}
```

### Production environment configuration

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
```

## Argument Reference

The following arguments are supported:

* `allowed_origins` - (Required) Set of origins permitted to make cross-origin requests. Use `"*"` as the only value to allow all origins. Must contain at least one origin.

* `allowed_headers` - (Optional) Set of additional custom headers allowed on cross-origin requests. Vault automatically includes standard headers, so only specify custom headers here. The standard headers that are always included are:
  - `Content-Type`
  - `X-Requested-With`
  - `X-Vault-AWS-IAM-Server-ID`
  - `X-Vault-MFA`
  - `X-Vault-No-Request-Forwarding`
  - `X-Vault-Wrap-Format`
  - `X-Vault-Wrap-TTL`
  - `X-Vault-Policy-Override`
  - `Authorization`
  - `X-Vault-Token`

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The ID of the CORS configuration. Always set to `sys/config/cors`.

* `enabled` - (Computed) Whether CORS is currently enabled. Vault automatically sets this to `true` when `allowed_origins` is configured, and `false` when CORS is deleted.

## Import

CORS configuration can be imported using the fixed ID `sys/config/cors`:

```
$ terraform import vault_sys_config_cors.example sys/config/cors
```

## Security Considerations

* The wildcard `"*"` origin should be used cautiously and typically only in development environments
* Allowing all origins in production can expose Vault to cross-site request forgery attacks
* Custom headers should be carefully reviewed to ensure they don't expose sensitive information
* CORS settings must be configured from the root namespace
* In Vault Enterprise with Performance Replication, CORS configuration does not replicate across clusters - each secondary cluster must have its CORS configuration set independently
* To disable CORS, delete the resource using `terraform destroy` or remove it from your configuration. There is no `enabled = false` option

## API Documentation

For more information on the Vault CORS configuration API, see the [Vault API documentation](https://developer.hashicorp.com/vault/api-docs/system/config-cors).