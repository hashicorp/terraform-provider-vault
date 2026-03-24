---
layout: "vault"
page_title: "Vault: vault_config_ui_header resource"
sidebar_current: "docs-vault-resource-config-ui-header"
description: |-
  Manages custom HTTP headers for the Vault UI
---

# vault\_config\_ui\_header

Manages custom HTTP headers for the Vault UI. This resource allows you to configure
custom HTTP response headers that will be sent by the Vault UI, enabling security
policies, CORS configuration, and custom organizational headers.

~> **Important** This resource requires **Vault 1.16.0 or later**. The `sys/config/ui/headers` API endpoint was introduced in Vault 1.16.0.

~> **Important** All operations on this resource require the `sudo` capability on the
`sys/config/ui/headers/*` path.

## Example Usage

### Basic Header Configuration

```hcl
resource "vault_config_ui_header" "custom" {
  name   = "X-Custom-Header"
  values = ["custom-value"]
}
```

### Security Headers

```hcl
# Content Security Policy
resource "vault_config_ui_header" "csp" {
  name = "Content-Security-Policy"
  values = [
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
  ]
}

# X-Frame-Options
resource "vault_config_ui_header" "frame_options" {
  name   = "X-Frame-Options"
  values = ["DENY"]
}

# Strict Transport Security
resource "vault_config_ui_header" "hsts" {
  name   = "Strict-Transport-Security"
  values = ["max-age=31536000; includeSubDomains; preload"]
}

# X-Content-Type-Options
resource "vault_config_ui_header" "content_type_options" {
  name   = "X-Content-Type-Options"
  values = ["nosniff"]
}
```

### CORS Configuration

```hcl
resource "vault_config_ui_header" "cors_origin" {
  name = "Access-Control-Allow-Origin"
  values = [
    "https://example.com",
    "https://app.example.com"
  ]
}

resource "vault_config_ui_header" "cors_methods" {
  name = "Access-Control-Allow-Methods"
  values = [
    "GET",
    "POST",
    "OPTIONS"
  ]
}

resource "vault_config_ui_header" "cors_headers" {
  name = "Access-Control-Allow-Headers"
  values = [
    "Content-Type",
    "Authorization"
  ]
}
```

### Multiple Values

```hcl
resource "vault_config_ui_header" "multi_value" {
  name = "X-Multi-Value-Header"
  values = [
    "value1",
    "value2",
    "value3"
  ]
}
```

### Namespace-Specific Header (Enterprise)

```hcl
resource "vault_namespace" "example" {
  path = "example"
}

resource "vault_config_ui_header" "ns_header" {
  namespace = vault_namespace.example.path
  name      = "X-Namespace-Header"
  values    = ["namespace-specific-value"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `name` - (Required, Forces new resource) The name of the custom header (e.g., "Content-Security-Policy", "X-Frame-Options").
  Changing this will recreate the resource.

* `values` - (Required) A list of values for the header. At least one value is required.
  Multiple values can be provided for headers that support them.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The resource identifier, which is the same as the `name`.

## Import

UI header configurations can be imported using the header `name`, e.g.

```
$ terraform import vault_config_ui_header.csp Content-Security-Policy
```

For namespace-specific headers in Vault Enterprise:

```
$ terraform import vault_config_ui_header.ns_header example/X-Namespace-Header
```

## Migration from vault_generic_endpoint

If you're currently managing UI headers using `vault_generic_endpoint`, you can migrate
to this dedicated resource:

### Before (using generic_endpoint)

```hcl
resource "vault_generic_endpoint" "csp_header" {
  path = "sys/config/ui/headers/Content-Security-Policy"
  data_json = jsonencode({
    values = ["default-src 'self'"]
  })
}
```

### After (using dedicated resource)

```hcl
resource "vault_config_ui_header" "csp" {
  name   = "Content-Security-Policy"
  values = ["default-src 'self'"]
}
```

### Migration Steps

1. Add the new `vault_config_ui_header` resource to your configuration
2. Import the existing header: `terraform import vault_config_ui_header.csp Content-Security-Policy`
3. Remove the old `vault_generic_endpoint` resource from your configuration
4. Run `terraform plan` to verify no changes are required

## Important Notes

### Sudo Capability Requirement

All operations on UI headers require the `sudo` capability. Ensure your Vault policy includes:

```hcl
path "sys/config/ui/headers/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
```

If you encounter permission errors, verify that your Vault token has the appropriate policy attached.

### Header Name Changes

The `name` field uses the `RequiresReplace` plan modifier. Changing the header name will
destroy the old header configuration and create a new one. If you need to rename a header,
you should:

1. Create the new header resource
2. Remove the old header resource
3. Apply the changes

### Multiple Values

Some HTTP headers support multiple values (e.g., CORS headers). This resource allows you
to specify multiple values in the `values` list. The order of values is preserved.

### Security Considerations

- Always use TLS/HTTPS for production Vault connections
- Carefully configure security headers (CSP, HSTS, etc.) to avoid breaking UI functionality
- Test header configurations in a non-production environment first
- Review the [Vault UI Headers API documentation](https://developer.hashicorp.com/vault/api-docs/system/config-ui-headers) for header-specific guidance

## See Also

- [Vault UI Headers API Documentation](https://developer.hashicorp.com/vault/api-docs/system/config-ui-headers)
- [Content Security Policy (CSP) Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [HTTP Headers Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)