---
layout: "vault"
page_title: "Vault: vault_oauth_resource_server_config_profile resource"
sidebar_current: "docs-vault-resource-sys-oauth-resource-server-config-profile"
description: |-
  Manages OAuth Resource Server Configuration profiles in Vault Enterprise.
---

# vault\_oauth\_resource\_server\_config\_profile

Manages OAuth Resource Server Configuration profiles in Vault Enterprise. These profiles define how Vault validates JWT tokens from OAuth 2.0 resource servers, enabling JWT-based authentication for API requests.

~> **Important** This resource is only available in Vault Enterprise and requires Vault 2.0.0 or later.

~> **Activation Flag Required** The OAuth Resource Server feature must be activated on each Vault instance before using this resource. Activate it using the Vault CLI: `vault write -f sys/activation-flags/oauth-resource-server/activate`. This is a one-time operation per Vault instance and must be performed outside of Terraform.

## Example Usage

### JWKS-Based Profile

```hcl
resource "vault_oauth_resource_server_config_profile" "example" {
  profile_name = "my-oauth-profile"
  issuer_id    = "https://auth.example.com"
  use_jwks     = true
  jwks_uri     = "https://auth.example.com/.well-known/jwks.json"
  audiences    = ["api.example.com", "vault.example.com"]
}
```

### PEM-Based Profile with Static Keys

```hcl
resource "vault_oauth_resource_server_config_profile" "pem_example" {
  profile_name = "my-pem-profile"
  issuer_id    = "https://auth.example.com"
  use_jwks     = false

  public_keys {
    key_id = "key-1"
    pem    = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
...
-----END PUBLIC KEY-----
EOT
  }

  public_keys {
    key_id = "key-2"
    pem    = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXxG8VqPvXxG8VqPvXxG
...
-----END PUBLIC KEY-----
EOT
  }
}
```

### Profile with Custom Configuration

```hcl
resource "vault_oauth_resource_server_config_profile" "advanced" {
  profile_name          = "advanced-profile"
  issuer_id             = "https://auth.example.com"
  use_jwks              = true
  jwks_uri              = "https://auth.example.com/.well-known/jwks.json"
  
  # Optional CA certificate for JWKS URI TLS validation
  jwks_ca_pem = file("${path.module}/ca-cert.pem")
  
  # Audience validation
  audiences = ["api.example.com"]
  
  # Custom user claim
  user_claim = "email"
  
  # Specific algorithms
  supported_algorithms = ["RS256", "ES256"]
  
  # JWT type
  jwt_type = "access_token"
  
  # Clock skew tolerance (in seconds)
  clock_skew_leeway = 30
  
  # Policy configuration
  no_default_policy = false
  
  # Enable/disable profile
  enabled = true
}
```

### Profile in a Namespace

```hcl
resource "vault_namespace" "app" {
  path = "application"
}

resource "vault_oauth_resource_server_config_profile" "namespaced" {
  namespace    = vault_namespace.app.path
  profile_name = "app-oauth-profile"
  issuer_id    = "https://auth.example.com"
  use_jwks     = true
  jwks_uri     = "https://auth.example.com/.well-known/jwks.json"
}
```

### Disabled Profile

```hcl
resource "vault_oauth_resource_server_config_profile" "disabled" {
  profile_name = "disabled-profile"
  issuer_id    = "https://auth.example.com"
  use_jwks     = true
  jwks_uri     = "https://auth.example.com/.well-known/jwks.json"
  enabled      = false
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `profile_name` - (Required) The name of the OAuth Resource Server Configuration profile. Must be unique within the namespace. Changing this will force a new resource to be created.

* `issuer_id` - (Required) The issuer ID (iss claim) to validate against in incoming JWTs. This should match the issuer claim in the JWT tokens. Changing this will force a new resource to be created.

* `use_jwks` - (Optional) If true, use JWKS URI for key validation; if false, use static public keys. Defaults to `true`. When set to true, `jwks_uri` is required. When set to false, `public_keys` is required.

* `jwks_uri` - (Optional) The JWKS URI to fetch public keys from. Required when `use_jwks=true`. This should be the URL where the authorization server publishes its public keys in JWKS format.

* `jwks_ca_pem` - (Optional) CA certificate (PEM format) for JWKS URI TLS validation. Use this when the JWKS URI uses a custom CA certificate.

* `public_keys` - (Optional) List of static public keys with `key_id` and `pem` fields. Required when `use_jwks=false`. Each public key must have:
  * `key_id` - (Required) The key ID (kid) for this public key. Must be unique within the profile.
  * `pem` - (Required) The PEM-encoded public key.

* `audiences` - (Optional) List of allowed audiences (aud claim) to validate in JWTs. If specified, the JWT must contain at least one of these audiences in its aud claim.

* `no_default_policy` - (Optional) If true, JWT-authenticated tokens omit the default policy unless added elsewhere. Defaults to `false`.

* `user_claim` - (Optional) The claim to use as the user identifier. Defaults to `sub`. This determines which JWT claim is used to identify the user.

* `supported_algorithms` - (Optional) List of supported signing algorithms (e.g., RS256, ES256). Defaults to all supported algorithms: `["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]`. Valid values are:
  * `RS256`, `RS384`, `RS512` - RSA with SHA-256/384/512
  * `ES256`, `ES384`, `ES512` - ECDSA with SHA-256/384/512
  * `PS256`, `PS384`, `PS512` - RSA-PSS with SHA-256/384/512

* `jwt_type` - (Optional) The JWT type: `access_token` or `transaction_token`. Defaults to `access_token`.

* `clock_skew_leeway` - (Optional) Leeway for clock skew in seconds when validating time-based claims (exp, iat, nbf). Defaults to `0`. Use this to account for clock differences between systems.

* `enabled` - (Optional) Whether this profile is enabled for JWT validation. Disabled profiles are ignored during JWT authentication. Defaults to `true`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `id` - The unique identifier for this resource (same as `config_id`). This is a stable UUID that persists across updates.

* `config_id` - Stable unique identifier for this profile within the namespace. This is the same value as `id` and persists across updates.

## Import

OAuth Resource Server Configuration profiles can be imported using the `profile_name`, e.g.

```
$ terraform import vault_oauth_resource_server_config_profile.example my-oauth-profile
```

For profiles in a namespace, use the format `namespace/profile_name`:

```
$ terraform import vault_oauth_resource_server_config_profile.example application/my-oauth-profile
```

## Notes

* **Mutual Exclusivity**: The `use_jwks` flag determines which configuration mode is active:
  * When `use_jwks=true`: You must provide `jwks_uri` and cannot provide `public_keys`
  * When `use_jwks=false`: You must provide `public_keys` and cannot provide `jwks_uri`

* **Issuer Uniqueness**: Each issuer ID must be unique within a namespace. You cannot have multiple profiles with the same issuer ID in the same namespace.

* **Profile Name Immutability**: The `profile_name` and `issuer_id` cannot be changed after creation. Changing these fields will force a new resource to be created.

* **Key ID Uniqueness**: Within a profile, all key IDs must be unique. This applies to both JWKS keys and static PEM keys.

* **JWKS Caching**: When using JWKS, Vault caches the public keys and refreshes them periodically. Unknown key IDs trigger a rate-limited refresh to prevent DoS attacks.

* **Algorithm Validation**: The JWT's signing algorithm must be in the `supported_algorithms` list. This provides defense against algorithm confusion attacks.

* **Audience Validation**: If `audiences` is specified, the JWT must contain at least one matching audience in its `aud` claim. If not specified, audience validation is skipped.

* **Clock Skew**: Use `clock_skew_leeway` to handle clock differences between systems. A value of 30-60 seconds is typically sufficient for most environments.

* **Activation Flag**: The OAuth Resource Server feature must be activated on each Vault instance before using this resource. Use the Vault CLI to activate: `vault write -f sys/activation-flags/oauth-resource-server/activate`. This is a one-time operation per Vault instance and cannot be performed through Terraform.

* **Enterprise Feature**: OAuth Resource Server Configuration is only available in Vault Enterprise. Attempting to use this resource with Vault Community Edition will result in an error.

* **Version Requirement**: This resource requires Vault 2.0.0 or later.

## Security Considerations

* **HTTPS for JWKS**: Always use HTTPS for `jwks_uri` to prevent man-in-the-middle attacks.

* **CA Certificate Validation**: When using custom CA certificates, ensure they are properly validated and from trusted sources.

* **Key Rotation**: When rotating keys, ensure the new keys are published to the JWKS endpoint before revoking old keys to prevent authentication failures.

* **Disabled Profiles**: Disabled profiles are completely ignored during JWT validation. Use this feature carefully in production environments.

* **Algorithm Selection**: Limit `supported_algorithms` to only those algorithms your authorization server uses. This reduces the attack surface.