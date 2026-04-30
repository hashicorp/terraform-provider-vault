---
layout: "vault"
page_title: "Vault: vault_generic_endpoint ephemeral resource"
sidebar_current: "docs-vault-ephemeral-resource-generic-endpoint"
description: |-
  Write to a generic Vault endpoint and extract response data as ephemeral values.
---

# vault\_generic\_endpoint (Ephemeral)

Writes to a generic Vault endpoint and extracts response data as ephemeral values that are not stored in Terraform state.
This is useful for authentication flows, token generation, or any Vault operation
where you need to extract sensitive data without persisting it to state.

~> **Important** All Vault ephemeral resources are supported from Terraform 1.10+.
Please refer to the [ephemeral resources usage guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources)
for additional information.

## Example Usage

### Basic Authentication (Extracting Auth Tokens)

```hcl
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

resource "vault_policy" "token_operations" {
  name = "token-operations"

  policy = <<EOT
path "auth/token/create" {
  capabilities = ["create", "update", "sudo"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOT
}

resource "vault_generic_endpoint" "user" {
  path                 = "auth/${vault_auth_backend.userpass.path}/users/myuser"
  ignore_absent_fields = true
  data_json = jsonencode({
    password = "changeme"
    policies = ["default", vault_policy.token_operations.name]
  })
}

# Login and extract token from response.Auth
ephemeral "vault_generic_endpoint" "login" {
  mount_id     = vault_generic_endpoint.user.id
  path         = "auth/${vault_auth_backend.userpass.path}/login/myuser"
  data_json    = jsonencode({
    password = "changeme"
  })
  write_fields = ["token", "accessor"]
}

# Use the ephemeral token with an aliased provider
provider "vault" {
  alias   = "user_auth"
  token   = ephemeral.vault_generic_endpoint.login.write_data["token"]
}

# Access Vault using the user's token
data "vault_generic_secret" "token_check" {
  provider = vault.user_auth
  path     = "auth/token/lookup-self"
}
```

### Response Wrapping (Extracting WrapInfo)

```hcl
# Create a wrapped token
ephemeral "vault_generic_endpoint" "wrapped_token" {
  path          = "auth/token/create"
  data_json     = jsonencode({
    policies = ["default"]
    ttl      = "1h"
  })
  # Enable response wrapping
  path_wrap_ttl = "300s"
  # Extract wrap_info fields
  write_fields  = ["token", "ttl", "creation_time", "wrapped_accessor"]
}

# The wrap token can be securely distributed
output "wrap_token" {
  value     = ephemeral.vault_generic_endpoint.wrapped_token.write_data["token"]
  sensitive = true
}
```

### DR Secondary Token Generation

```hcl
# Generate DR secondary token with response wrapping
ephemeral "vault_generic_endpoint" "dr_secondary_token" {
  path          = "sys/replication/dr/primary/secondary-token"
  path_wrap_ttl = "30m"
  write_fields  = ["token", "ttl", "creation_time"]
  data_json     = jsonencode({
    id = "dr-secondary-1"
  })
}

output "dr_token" {
  value     = ephemeral.vault_generic_endpoint.dr_secondary_token.write_data["token"]
  sensitive = true
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The Vault namespace to use.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Required) The full path to the Vault endpoint that will be written to.

* `data_json` - (Required, Sensitive) JSON-encoded data to write to the endpoint.

* `write_fields` - (Optional) List of top-level fields returned by the write operation
  to extract and make available in `write_data`. Fields can come from:
  - `response.Auth` - e.g., `token`, `accessor`, `policies`
  - `response.WrapInfo` - e.g., `token`, `ttl`, `creation_time`, `wrapped_accessor`
  - `response.Data` - Any fields in the response data
  
  Special field mappings:
  - `"token"` automatically maps to `client_token` from `response.Auth`
  - `"wrap_info"` returns the entire WrapInfo structure as JSON
  - `"auth"` returns the entire Auth structure as JSON

* `path_wrap_ttl` - (Optional) The TTL for response wrapping. When set, Vault will
  wrap the response and return a wrapping token instead of the actual response.
  The value should be a duration string like `"30s"`, `"5m"`, or `"1h"`.
  When enabled, `write_fields` should extract from WrapInfo fields.

* `mount_id` - (Optional) The ID of a resource that this ephemeral resource depends on.
  This ensures proper ordering of operations when the ephemeral resource depends on
  infrastructure resources like auth backends or secret engines.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `write_data` - A map of strings containing the extracted fields specified in
  `write_fields`. Access individual fields using `write_data["field_name"]`.

* `write_data_json` - JSON string containing all extracted fields from `write_fields`.

## Response Field Extraction

The resource extracts fields in the following order:

1. **response.Data** - Direct response data fields
2. **response.WrapInfo** - Wrapped response fields (when `path_wrap_ttl` is set)
   - Individual fields: `token`, `ttl`, `creation_time`, `wrapped_accessor`
   - Full structure: Use `"wrap_info"` in `write_fields`
3. **response.Auth** - Authentication response fields
   - Individual fields: `accessor`, `policies`, `lease_duration`
   - Token field: `"token"` maps to `client_token`
   - Full structure: Use `"auth"` in `write_fields`
4. **Top-level response** - `lease_duration`, `lease_id`, `renewable`

## Important Notes

~> **Important** Ephemeral resources are designed for sensitive data that should not be stored in Terraform state. However, the data can still appear in console output when Terraform runs and may be included in plan files if secrets are interpolated into resource attributes. Protect these artifacts accordingly.

* **Use with provider aliases** - The most common pattern is to extract a token
  and use it with a Vault provider alias (see examples above).

* **Response wrapping** - When `path_wrap_ttl` is set, Vault returns a wrapping
  token instead of the actual response. The wrapping token is a single-use token
  that must be unwrapped to retrieve the original response. **Important**: A wrapped
  token cannot be used directly for authentication - it must first be unwrapped using
  Vault's `sys/wrapping/unwrap` endpoint or the `vault unwrap` CLI command. This is
  a security feature that allows secure distribution of secrets where the wrapping
  token can be given to a recipient who then unwraps it to get the actual secret.
  See [Vault Response Wrapping](https://developer.hashicorp.com/vault/docs/concepts/response-wrapping)
  for more details.

* **Sensitive data** - All extracted fields are marked as sensitive in Terraform
  and will not be displayed in plan or apply output.

## See Also

* [vault_generic_endpoint resource](../r/generic_endpoint.html) - For persistent
  Vault endpoint management
* [Ephemeral Resources Usage Guide](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources)
* [Vault Response Wrapping](https://developer.hashicorp.com/vault/docs/concepts/response-wrapping)
