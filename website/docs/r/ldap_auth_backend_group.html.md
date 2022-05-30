---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-ldap-auth-backend-group"
description: |-
  Managing groups in an LDAP auth backend in Vault
---

# vault\_ldap\_auth\_backend\_group

Provides a resource to create a group in an [LDAP auth backend within Vault](https://www.vaultproject.io/docs/auth/ldap.html).

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

resource "vault_ldap_auth_backend_group" "group" {
    groupname = "dba"
    policies  = ["dba"]
    backend   = vault_ldap_auth_backend.ldap.path
}
```

## Argument Reference

The following arguments are supported:

* `groupname` - (Required) The LDAP groupname

* `policies` - (Optional) Policies which should be granted to members of the group

* `backend` - (Optional) Path to the authentication backend

For more details on the usage of each argument consult the [Vault LDAP API documentation](https://www.vaultproject.io/api-docs/auth/ldap).

## Attribute Reference

No additional attributes are exposed by this resource.

## Import

LDAP authentication backend groups can be imported using the `path`, e.g.

```
$ terraform import vault_ldap_auth_backend_group.foo auth/ldap/groups/foo
```
