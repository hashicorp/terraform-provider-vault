---
layout: "vault"
page_title: "Vault: vault_kerberos_auth_backend_group resource"
sidebar_current: "docs-vault-resource-kerberos-auth-backend-group"
description: |-
  Manages LDAP group to Vault policy mappings for the Kerberos authentication method in Vault.
---

# vault\_kerberos\_auth\_backend\_group

Manages LDAP group to Vault policy mappings for the Kerberos authentication method in Vault.

This resource allows you to map LDAP groups to Vault policies when using the Kerberos 
authentication method. After a user successfully authenticates via Kerberos, Vault queries 
LDAP to determine the user's group memberships. These group mappings then 
determine which Vault policies are assigned to the authenticated user's token.

For more information, see the
[Vault Kerberos Auth Method documentation](https://www.vaultproject.io/docs/auth/kerberos).

~> **Note** This resource requires that LDAP integration be configured for the Kerberos 
auth method using [`vault_kerberos_auth_backend_ldap_config`](kerberos_auth_backend_ldap_config.html). 
Without LDAP configuration, group mappings cannot be resolved.

## Example Usage

### Basic Group Mapping

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
}

resource "vault_kerberos_auth_backend_config" "kerberos" {
  mount           = vault_auth_backend.kerberos.path
  keytab          = filebase64("/path/to/vault.keytab")
  service_account = "vault/localhost@EXAMPLE.COM"
}

resource "vault_kerberos_auth_backend_ldap_config" "ldap" {
  mount  = vault_auth_backend.kerberos.path
  url    = "ldap://ldap.example.com"
  binddn = "cn=vault,ou=Users,dc=example,dc=com"
  userdn = "ou=People,dc=example,dc=org"
  groupdn = "ou=Groups,dc=example,dc=org"
}

resource "vault_kerberos_auth_backend_group" "developers" {
  mount    = vault_auth_backend.kerberos.path
  name     = "developers"
  policies = ["dev-policy", "read-only"]
}
```

### Multiple Group Mappings

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
}

resource "vault_kerberos_auth_backend_group" "admins" {
  mount    = vault_auth_backend.kerberos.path
  name     = "admins"
  policies = ["admin-policy", "default"]
}

resource "vault_kerberos_auth_backend_group" "developers" {
  mount    = vault_auth_backend.kerberos.path
  name     = "developers"
  policies = ["dev-policy", "default"]
}

resource "vault_kerberos_auth_backend_group" "readonly" {
  mount    = vault_auth_backend.kerberos.path
  name     = "readonly-users"
  policies = ["read-only"]
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

resource "vault_kerberos_auth_backend_group" "team" {
  namespace = vault_namespace.example.path
  mount     = vault_auth_backend.kerberos.path
  name      = "team-alpha"
  policies  = ["team-alpha-policy"]
}
```

### Group Without Policies

```hcl
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = "kerberos"
}

# Create a group mapping without policies
# Useful for tracking groups or for later policy assignment
resource "vault_kerberos_auth_backend_group" "contractors" {
  mount = vault_auth_backend.kerberos.path
  name  = "contractors"
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

* `name` - (Required) The name of the LDAP group to map to Vault policies. 
  This should match the group name as it appears in your LDAP directory. 
  Changing this will force a new resource to be created.

* `policies` - (Optional) Set of Vault policy names to associate with this group. 
  Users who are members of this LDAP group will receive these policies when they 
  authenticate via Kerberos.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Kerberos auth backend group mappings can be imported using the path, e.g.

```
$ terraform import vault_kerberos_auth_backend_group.developers auth/kerberos/groups/developers
```

### Importing with Namespace (Vault Enterprise)

For Vault Enterprise with namespaces, set the `TERRAFORM_VAULT_NAMESPACE_IMPORT` environment variable 
before importing:

```
$ export TERRAFORM_VAULT_NAMESPACE_IMPORT=example-namespace
$ terraform import vault_kerberos_auth_backend_group.developers auth/kerberos/groups/developers