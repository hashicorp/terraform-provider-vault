---
layout: "vault"
page_title: "Vault: vault_kerberos_auth_backend_ldap_config resource"
sidebar_current: "docs-vault-resource-kerberos-auth-backend-ldap-config"
description: |-
  Manages LDAP configuration for the Kerberos authentication method in Vault.
---

# vault\_kerberos\_auth\_backend\_ldap\_config

Manages LDAP configuration for the Kerberos authentication method in Vault.

This resource configures LDAP integration for the Kerberos auth method, allowing Vault to 
query LDAP for user and group information after successful Kerberos authentication. This 
enables group-based policy assignment and additional user metadata retrieval.

For more information, see the
[Vault Kerberos Auth Method documentation](https://www.vaultproject.io/docs/auth/kerberos).

~> **Important** The `certificate` field is marked as sensitive and will be stored in state
files (but masked in output). Write-only fields (`bindpass_wo`, `client_tls_cert_wo`,
`client_tls_key_wo`) are not stored in state and are only sent to Vault during configuration.
Protect state files accordingly. See [the main provider documentation](../index.html) for more details.

~> **Note** Vault does not support deleting auth backend LDAP configurations via the API.
When this resource is destroyed or replaced (e.g., when changing the `mount`), it is 
only removed from Terraform state. The configuration remains in Vault until the auth 
mount itself is deleted.

## Example Usage

### Basic Configuration

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
}

resource "vault_kerberos_auth_backend_config" "kerberos" {
  mount             = vault_auth_backend.kerberos.path
  keytab_wo         = filebase64("/path/to/vault.keytab")
  keytab_wo_version = 1
  service_account   = "vault/localhost@EXAMPLE.COM"
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount  = vault_auth_backend.kerberos.path
  url    = "ldap://ldap.example.com"
  binddn = "cn=vault,ou=Users,dc=example,dc=com"
  userdn = "ou=People,dc=example,dc=org"
}
```

### Configuration with Bind Password

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount               = vault_auth_backend.kerberos.path
  url                 = "ldap://ldap.example.com"
  binddn              = "cn=vault,ou=Users,dc=example,dc=com"
  bindpass_wo         = var.ldap_bind_password
  bindpass_wo_version = 1
  userdn              = "ou=People,dc=example,dc=org"
}
```

### Full Configuration with TLS and Groups

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount                   = vault_auth_backend.kerberos.path
  url                     = "ldaps://ldap.example.com:636"
  binddn                  = "cn=vault,ou=Users,dc=example,dc=com"
  bindpass_wo             = var.ldap_bind_password
  bindpass_wo_version     = 1
  userdn                  = "ou=People,dc=example,dc=org"
  userattr                = "samaccountname"
  groupdn                 = "ou=Groups,dc=example,dc=org"
  groupfilter             = "(objectClass=group)"
  groupattr               = "cn"
  use_token_groups        = true
  tls_min_version         = "tls12"
  tls_max_version         = "tls13"
  certificate             = file("/path/to/ca-cert.pem")
  deny_null_bind          = true
  
  # Token configuration
  token_ttl               = 1800
  token_max_ttl           = 3600
  token_policies          = ["default", "dev"]
  token_type              = "service"
}
```

### Configuration with Client TLS Certificates

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  mount                      = vault_auth_backend.kerberos.path
  url                        = "ldaps://ldap.example.com:636"
  binddn                     = "cn=vault,ou=Users,dc=example,dc=com"
  userdn                     = "ou=People,dc=example,dc=org"
  certificate                = file("/path/to/ca-cert.pem")
  client_tls_cert_wo         = file("/path/to/client-cert.pem")
  client_tls_cert_wo_version = 1
  client_tls_key_wo          = file("/path/to/client-key.pem")
  client_tls_key_wo_version  = 1
}
```

### Using Namespace (Vault Enterprise)

```hcl
resource "vault_namespace" "example" {
  path = "example-namespace"
}

resource "vault_auth_backend" "kerberos" {
  namespace = vault_namespace.example.path
  type      = "kerberos"
  path      = "kerberos"
}

resource "vault_kerberos_auth_backend_ldap_config" "config" {
  namespace = vault_namespace.example.path
  mount     = vault_auth_backend.kerberos.path
  url       = "ldap://ldap.example.com"
  binddn    = "cn=vault,ou=Users,dc=example,dc=com"
  userdn    = "ou=People,dc=example,dc=org"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `mount` - (Required) Path where the Kerberos auth method is mounted.
  Changing this will force a new resource to be created.

### LDAP Connection Settings

* `url` - (Optional) LDAP URL to connect to. Multiple URLs can be specified by concatenating 
  them with commas (e.g., `ldap://ldap1.example.com,ldap://ldap2.example.com`). 
  Defaults to `ldap://127.0.0.1`.

* `starttls` - (Optional) Issue a StartTLS command after establishing an unencrypted connection. 
  Defaults to `false`.

* `insecure_tls` - (Optional) Skip TLS certificate verification. Not recommended for production use. 
  Defaults to `false`.

* `tls_min_version` - (Optional) Minimum TLS version to use. Accepted values are `tls10`, `tls11`, 
  `tls12`, or `tls13`. Defaults to `tls12`.

* `tls_max_version` - (Optional) Maximum TLS version to use. Accepted values are `tls10`, `tls11`, 
  `tls12`, or `tls13`. Defaults to `tls12`.

* `certificate` - (Optional) CA certificate to use when verifying LDAP server certificate. 
  Must be x509 PEM encoded.

* `client_tls_cert_wo` - (Optional) Client certificate to provide to the LDAP server. 
  Must be x509 PEM encoded. This is a write-only field. Must be used together with 
  `client_tls_cert_wo_version`.

* `client_tls_cert_wo_version` - (Optional) Version identifier for client TLS certificate updates. 
  Change this value to trigger a certificate update. Must be used together with `client_tls_cert_wo`.

* `client_tls_key_wo` - (Optional) Client certificate key to provide to the LDAP server. 
  Must be x509 PEM encoded. This is a write-only field. Must be used together with 
  `client_tls_key_wo_version`.

* `client_tls_key_wo_version` - (Optional) Version identifier for client TLS key updates. 
  Change this value to trigger a key update. Must be used together with `client_tls_key_wo`.

* `request_timeout` - (Optional) Timeout, in seconds, for the connection when making requests 
  against the server. Defaults to `90`.

* `connection_timeout` - (Optional) Timeout, in seconds, when attempting to connect to the 
  LDAP server. Defaults to `30`.

### LDAP Bind Settings

* `binddn` - (Optional) Distinguished name of object to bind when performing user and group search 
  (e.g., `cn=vault,ou=Users,dc=example,dc=com`).

* `bindpass_wo` - (Optional) LDAP password for searching for the user DN. This is a write-only field. 
  Must be used together with `bindpass_wo_version`.

* `bindpass_wo_version` - (Optional) Version identifier (integer) for bind password updates. Change this value
  to trigger a password update. Must be used together with `bindpass_wo`.

* `deny_null_bind` - (Optional) Denies an unauthenticated LDAP bind request if the user's password 
  is empty. Defaults to `true`.

* `discoverdn` - (Optional) Use anonymous bind to discover the bind DN of a user. Defaults to `false`.

### User Search Settings

* `userdn` - (Optional) LDAP domain to use for users (e.g., `ou=People,dc=example,dc=org`).

* `userattr` - (Optional) Attribute used for users. Common values include `samaccountname` and `uid`. 
  Defaults to `cn`.

* `userfilter` - (Optional) Go template for querying user search. The template can access the 
  following context variables: `UserAttr`, `Username`. Defaults to `({{.UserAttr}}={{.Username}})`.

* `upndomain` - (Optional) The userPrincipalDomain used to construct the UPN string for the authenticating user. The constructed UPN will appear as `[username]@UPNDomain`.

* `username_as_alias` - (Optional) Use username as alias name. Defaults to `false`.

* `enable_samaccountname_login` - (Optional) If true, matching sAMAccountName attribute values
  will be allowed to login when `upndomain` is defined. Defaults to `false`.
  **Note:** This field is only supported in Vault 1.19.0 and above. If configured for vault version lesser than 1.21.0, this field will be ignored, even though the value is persisted in the state file.

### Group Search Settings

* `groupdn` - (Optional) LDAP search base to use for group membership search 
  (e.g., `ou=Groups,dc=example,dc=org`).

* `groupfilter` - (Optional) Go template for querying group membership of user. The template can 
  access the following context variables: `UserDN`, `Username`. Defaults to 
  `(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))`.

* `groupattr` - (Optional) LDAP attribute to follow on objects returned by `groupfilter` in order 
  to enumerate user group membership. Defaults to `cn`.

* `anonymous_group_search` - (Optional) Use anonymous binds when performing LDAP group searches 
  (if true, the initial credentials will still be used for the initial connection test). 
  Defaults to `false`.

* `use_token_groups` - (Optional) If true, use the Active Directory tokenGroups constructed attribute 
  of the user to find the group memberships. This will find all security groups including nested ones. 
  Defaults to `false`.

* `case_sensitive_names` - (Optional) If true, case sensitivity will be used when comparing usernames 
  and groups for matching policies. Defaults to `false`.

### Advanced Settings

* `dereference_aliases` - (Optional) When aliases should be dereferenced on search operations. 
  Accepted values are `never`, `finding`, `searching`, or `always`. Defaults to `never`.

* `max_page_size` - (Optional) If set to a value greater than 0, the LDAP backend will use the 
  LDAP server's paged search control to request pages of up to the given size. This can be used 
  to avoid hitting the LDAP server's maximum result size limit. Otherwise, the LDAP backend will 
  not use the paged search control. Defaults to `0`.

### Token Settings

For more information on token settings, see the [Token Fields documentation](/docs/providers/vault/index.html#token-fields).

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in seconds. 
  Its current value will be referenced at renewal time.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in seconds. 
  Its current value will be referenced at renewal time.

* `token_period` - (Optional) The maximum allowed period value when a periodic token is requested from this role.

* `token_policies` - (Optional) List of policies to encode onto generated tokens. Depending 
  on the auth method, this list may be supplemented by user/group/other values.

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks of IP 
  addresses which can authenticate successfully, and ties the resulting token to these blocks 
  as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an explicit max TTL onto the token 
  in seconds. This is a hard cap even if `token_ttl` and `token_max_ttl` would otherwise allow 
  a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on 
  generated tokens; otherwise it will be added to the policies set in `token_policies`.

* `token_num_uses` - (Optional) The maximum number of times a generated token may be used 
  (within its lifetime); 0 means unlimited. If you require the token to have the ability to 
  create child tokens, you will need to set this value to 0.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

* `alias_metadata` - (Optional) A map of string to string that will be set as metadata on
  the identity alias. **Note:** Supported in Vault-enterprise v1.21.0+

## Import

Kerberos auth backend LDAP configurations can be imported using the `auth/{mount}/config/ldap` path, e.g.

```
$ terraform import vault_kerberos_auth_backend_ldap_config.config auth/kerberos/config/ldap
```

~> **Note** Write-only fields (`bindpass_wo`, `client_tls_cert_wo`, `client_tls_key_wo`) and 
their version fields cannot be imported. You will need to ignore changes to these fields or 
provide them in your configuration after import.

### Importing with Namespace (Vault Enterprise)

For Vault Enterprise with namespaces, set the `TERRAFORM_VAULT_NAMESPACE_IMPORT` environment variable 
before importing:

```
$ export TERRAFORM_VAULT_NAMESPACE_IMPORT=example-namespace
$ terraform import vault_kerberos_auth_backend_ldap_config.config auth/kerberos/config/ldap