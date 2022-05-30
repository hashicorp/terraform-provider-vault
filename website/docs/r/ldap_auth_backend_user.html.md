---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-ldap-auth-backend-user"
description: |-
  Managing users in an LDAP auth backend in Vault
---

# vault\_ldap\_auth\_backend\_user

Provides a resource to create a user in an [LDAP auth backend within Vault](https://www.vaultproject.io/docs/auth/ldap.html).

## Example Usage

```hcl
resource "vault_ldap_auth_backend" "ldap" {
    path        = "ldap"
    url         = "ldaps://dc-01.example.org"
    userdn      = "OU=Users,OU=Accounts,DC=example,DC=org"
    userattr    = "sAMAccountName"
    upndomain   = "EXAMPLE.ORG"
    discoverdn  = false
    groupdn     = "OU=Groups,DC=example,DC=org"
    groupfilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
}

resource "vault_ldap_auth_backend_user" "user" {
    username = "test-user"
    policies = ["dba", "sysops"]
    backend  = vault_ldap_auth_backend.ldap.path
}
```

## Argument Reference

The following arguments are supported:

* `username` - (Required) The LDAP username

* `policies` - (Optional) Policies which should be granted to user

* `groups` - (Optional) Override LDAP groups which should be granted to user

* `backend` - (Optional) Path to the authentication backend

For more details on the usage of each argument consult the [Vault LDAP API documentation](https://www.vaultproject.io/api-docs/auth/ldap).

## Attribute Reference

No additional attributes are exposed by this resource.

## Import

LDAP authentication backend users can be imported using the `path`, e.g.

```
$ terraform import vault_ldap_auth_backend_user.foo auth/ldap/users/foo
```
