---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-ldap-auth-backend"
description: |-
  Managing LDAP auth backends in Vault
---

# vault\_ldap\_auth\_backend

Provides a resource for managing an [LDAP auth backend within Vault](https://www.vaultproject.io/docs/auth/ldap.html).

## Example Usage

```hcl
resource "vault_ldap_auth_backend" "ldap" {
    path        = "${vault_auth_backend.ldap.path}"
    url         = "ldaps://dc-01.example.org"
    userdn      = "OU=Users,OU=Accounts,DC=example,DC=org"
    userattr    = "sAMAccountName"
    upndomain   = "EXAMPLE.ORG"
    discoverdn  = false
    groupdn     = "OU=Groups,DC=example,DC=org"
    groupfilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
}
```

## Argument Reference

The following arguments are supported:

* `url` - (Required) The URL of the LDAP server

* `startls` - (Optional) Control use of TLS when conecting to LDAP

* `tls_min_version` - (Optional) Minimum acceptable version of TLS

* `tls_max_version` - (Optional) Maximum acceptable version of TLS

* `insecure_tls` - (Optional) Control whether or TLS certificates must be validated

* `certificate` - (Optional) Trusted CA to validate TLS certificate

* `binddn` - (Optional) DN of object to bind when performing user search

* `bindpass` - (Optional) Password to use with `binddn` when performing user search

* `userdn` - (Optional) Base DN under which to perform user search

* `userattr` - (Optional) Attribute on user object matching username passed in

* `upndomain` - (Optional) The userPrincipalDomain used to construct UPN string

* `groupfilter` - (Optional) Go template used to construct group membership query

* `groupdn` - (Optional) Base DN under which to perform group search

* `groupattr` - (Optional) LDAP attribute to follow on objects returned by groupfilter

* `path` - (Optional) Path to mount the LDAP auth backend under

* `description` - (Optional) Description for the LDAP auth backend mount

For more details on the usage of each argument consult the [Vault LDAP API documentation](https://www.vaultproject.io/api/auth/ldap/index.html).

## Attribute Reference

No additional attributes are exposed by this resource.
