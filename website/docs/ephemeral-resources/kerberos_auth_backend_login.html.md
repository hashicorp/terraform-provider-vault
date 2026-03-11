---
layout: "vault"
page_title: "Vault: ephemeral vault_kerberos_auth_backend_login data resource"
sidebar_current: "docs-vault-ephemeral-kerberos-auth-backend-login"
description: |-
  Authenticate to Vault using Kerberos and obtain ephemeral credentials

---

# vault_kerberos_auth_backend_login (Ephemeral)

Performs Kerberos authentication and returns an ephemeral Vault token.  
These credentials are not stored in Terraform state and are automatically revoked when no longer needed.

This ephemeral resource authenticates to Vault using Kerberos credentials (keytab file) and returns a Vault token that can be used for subsequent operations. The token is automatically revoked when the Terraform configuration is no longer active.

For more information, refer to
the [Vault Kerberos Auth documentation](https://developer.hashicorp.com/vault/docs/auth/kerberos).

## Example Usage

### Basic Usage

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
  
  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_kerberos_auth_backend_config" "config" {
  mount           = vault_auth_backend.kerberos.path
  keytab          = filebase64("/path/to/vault.keytab")
  service_account = "vault/localhost@EXAMPLE.COM"
}

resource "vault_kerberos_auth_backend_ldap_config" "ldap" {
  mount    = vault_auth_backend.kerberos.path
  url      = "ldap://localhost:389"
  binddn   = "cn=admin,dc=example,dc=com"
  bindpass = "admin-password"
  userdn   = "ou=users,dc=example,dc=com"
  userattr = "uid"
}

ephemeral "vault_kerberos_auth_backend_login" "login" {
  mount         = vault_auth_backend.kerberos.path
  mount_id      = vault_auth_backend.kerberos.id
  keytab_path   = "/path/to/user.keytab"
  krb5conf_path = "/etc/krb5.conf"
  username      = "user1"
  service       = "vault/localhost"
  realm         = "EXAMPLE.COM"
  
  depends_on = [
    vault_kerberos_auth_backend_config.config,
    vault_kerberos_auth_backend_ldap_config.ldap
  ]
}

# Use the ephemeral token for authentication
provider "vault" {
  alias = "kerberos_auth"
  token = ephemeral.vault_kerberos_auth_backend_login.login.client_token
}
```

### With Optional Parameters

```hcl
ephemeral "vault_kerberos_auth_backend_login" "login" {
  mount                    = vault_auth_backend.kerberos.path
  mount_id                 = vault_auth_backend.kerberos.id
  keytab_path              = "/path/to/user.keytab"
  krb5conf_path            = "/etc/krb5.conf"
  username                 = "user1"
  service                  = "vault/localhost"
  realm                    = "EXAMPLE.COM"
  disable_fast_negotiation = true
  remove_instance_name     = true
  
  depends_on = [
    vault_kerberos_auth_backend_config.config,
    vault_kerberos_auth_backend_ldap_config.ldap
  ]
}
```

### Using Default Mount Path

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  
  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

ephemeral "vault_kerberos_auth_backend_login" "login" {
  mount_id      = vault_auth_backend.kerberos.id
  keytab_path   = "/path/to/user.keytab"
  krb5conf_path = "/etc/krb5.conf"
  username      = "user1"
  service       = "vault/localhost"
  realm         = "EXAMPLE.COM"
  
  depends_on = [
    vault_kerberos_auth_backend_config.config,
    vault_kerberos_auth_backend_ldap_config.ldap
  ]
}
```

### Using with Namespaces (Vault Enterprise)

```hcl
resource "vault_namespace" "app" {
  path = "app-team"
}

resource "vault_auth_backend" "kerberos" {
  namespace = vault_namespace.app.path
  type      = "kerberos"
  path      = "kerberos"
  
  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_kerberos_auth_backend_config" "config" {
  namespace       = vault_namespace.app.path
  mount           = vault_auth_backend.kerberos.path
  keytab          = filebase64("/path/to/vault.keytab")
  service_account = "vault/localhost@EXAMPLE.COM"
}

resource "vault_kerberos_auth_backend_ldap_config" "ldap" {
  namespace = vault_namespace.app.path
  mount     = vault_auth_backend.kerberos.path
  url       = "ldap://localhost:389"
  binddn    = "cn=admin,dc=example,dc=com"
  bindpass  = "admin-password"
  userdn    = "ou=users,dc=example,dc=com"
  userattr  = "uid"
}

ephemeral "vault_kerberos_auth_backend_login" "login" {
  namespace     = vault_namespace.app.path
  mount         = vault_auth_backend.kerberos.path
  mount_id      = vault_auth_backend.kerberos.id
  keytab_path   = "/path/to/user.keytab"
  krb5conf_path = "/etc/krb5.conf"
  username      = "user1"
  service       = "vault/localhost"
  realm         = "EXAMPLE.COM"
  
  depends_on = [
    vault_kerberos_auth_backend_config.config,
    vault_kerberos_auth_backend_ldap_config.ldap
  ]
}

# Use the ephemeral token for authentication in the namespace
provider "vault" {
  alias     = "kerberos_auth"
  namespace = vault_namespace.app.path
  token     = ephemeral.vault_kerberos_auth_backend_login.login.client_token
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Optional) Path where the Kerberos auth method is mounted. Defaults to `kerberos`.

* `mount_id` - (Optional) If value is set, will defer provisioning the ephemeral resource until
  `terraform apply`. For more details, please refer to the official documentation around
  [using ephemeral resources in the Vault Provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_ephemeral_resources).

* `keytab_path` - (Required) Path to the keytab file for authentication. This file must contain valid Kerberos credentials for the specified username.

* `krb5conf_path` - (Required) Path to the krb5.conf configuration file. This file contains Kerberos realm and KDC configuration.

* `username` - (Required) Username for the keytab entry. This must match a service account configured in LDAP.

* `service` - (Required) Service principal name for obtaining a service ticket (e.g., `vault/localhost` or `HTTP/vault.example.com`).

* `realm` - (Required) Kerberos realm name (e.g., `EXAMPLE.COM`). This must match the UPNDomain configured in the LDAP configuration.

* `disable_fast_negotiation` - (Optional) Disable FAST (Flexible Authentication Secure Tunneling) negotiation. Defaults to `false`.

* `remove_instance_name` - (Optional) Remove instance name from the service principal. Defaults to `false`.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `client_token` - The Vault token returned after successful authentication. This value is sensitive and ephemeral - it is not stored in Terraform state and is automatically revoked when the Terraform configuration is no longer active.

* `accessor` - The accessor for the token. This unique ID can be safely logged and used to track or revoke the token.

* `policies` - Set of policies attached to the token.

* `token_policies` - Policies from the token configuration.

* `identity_policies` - Policies from the identity.

* `metadata` - Metadata associated with the token.

* `lease_duration` - Token lease duration in seconds.

* `renewable` - Whether the token is renewable.

* `entity_id` - The identifier of the entity in the identity store.

* `token_type` - The type of token (service, batch, or default).

* `orphan` - Whether the token is orphaned.

* `num_uses` - Number of allowed uses of the issued token.

## Important Notes

### Authentication Backend Configuration

Before using this ephemeral resource, you must properly configure the Kerberos authentication backend:

1. **Enable the Kerberos auth method** with the required `tune` block to pass through the Authorization header:
   ```hcl
   resource "vault_auth_backend" "kerberos" {
     type = "kerberos"
     
     tune {
       passthrough_request_headers = ["Authorization"]
     }
   }
   ```

2. **Configure the Kerberos backend** with a valid keytab and service account using [`vault_kerberos_auth_backend_config`](../r/kerberos_auth_backend_config.html).

3. **Configure LDAP integration** using [`vault_kerberos_auth_backend_ldap_config`](../r/kerberos_auth_backend_ldap_config.html) to map Kerberos principals to Vault entities and policies.

### Dependencies

It is **strongly recommended** to use `depends_on` to ensure the Kerberos backend and LDAP configuration are fully set up before attempting authentication:

```hcl
ephemeral "vault_kerberos_auth_backend_login" "login" {
  # ... configuration ...
  
  depends_on = [
    vault_kerberos_auth_backend_config.config,
    vault_kerberos_auth_backend_ldap_config.ldap
  ]
}
```

### Automatic Token Revocation

Unlike regular authentication resources, this ephemeral version automatically revokes the Vault token when:

- The Terraform run completes
- The ephemeral resource is no longer referenced in the configuration
- An error occurs during the Terraform apply

This makes it ideal for temporary authentication scenarios where you want to ensure credentials are cleaned up automatically.

### Kerberos Environment Requirements

To use this resource, you need:

- A properly configured Kerberos environment with a running KDC (Key Distribution Center)
- Valid keytab files for the users who will authenticate
- A krb5.conf configuration file with realm and KDC information
- LDAP server integration for user and group mapping
- Network connectivity to the KDC and LDAP server

## See Also

* [vault_auth_backend](../r/auth_backend.html) - Enable auth backends in Vault
* [vault_kerberos_auth_backend_config](../r/kerberos_auth_backend_config.html) - Configure the Kerberos auth backend
* [vault_kerberos_auth_backend_ldap_config](../r/kerberos_auth_backend_ldap_config.html) - Configure LDAP integration for Kerberos auth
* [Vault Kerberos Auth Method](https://developer.hashicorp.com/vault/docs/auth/kerberos) - Official Vault documentation