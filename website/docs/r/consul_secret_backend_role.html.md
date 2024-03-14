---
layout: "vault"
page_title: "Vault: vault_consul_secret_backend_role resource"
sidebar_current: "docs-vault-resource-consul-secret-backend-role"
description: |-
  Manages a Consul secrets role for a Consul secrets engine in Vault.
---

# vault\_consul\_secret\_backend\_role

Manages a Consul secrets role for a Consul secrets engine in Vault. Consul secret backends can then issue Consul tokens.

## Example Usage

```hcl
resource "vault_consul_secret_backend" "test" {
  path        = "consul"
  description = "Manages the Consul backend"

  address = "127.0.0.1:8500"
  token   = "4240861b-ce3d-8530-115a-521ff070dd29"
}

resource "vault_consul_secret_backend_role" "example" {
  name    = "test-role"
  backend = vault_consul_secret_backend.test.path

  consul_policies = [
    "example-policy",
  ]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Optional) The unique name of an existing Consul secrets backend mount. Must not begin or end with a `/`. One of `path` or `backend` is required.

* `name` - (Required) The name of the Consul secrets engine role to create.

* `policies` - (Optional) The list of Consul ACL policies to associate with these roles.
  **NOTE:** The new parameter `consul_policies` should be used in favor of this. This parameter,
  `policies`, remains supported for legacy users, but Vault has deprecated this field.

* `consul_policies` - (Optional)<sup><a href="#note-about-required-arguments">SEE NOTE</a></sup> The list of Consul ACL policies to associate with these roles.

* `consul_roles` - (Optional)<sup><a href="#note-about-required-arguments">SEE NOTE</a></sup> Set of Consul roles to attach to the token.
   Applicable for Vault 1.10+ with Consul 1.5+.

* `service_identities` - (Optional)<sup><a href="#note-about-required-arguments">SEE NOTE</a></sup> Set of Consul
service identities to attach to the token. Applicable for Vault 1.11+ with Consul 1.5+.

* `node_identities` - (Optional)<sup><a href="#note-about-required-arguments">SEE NOTE</a></sup> Set of Consul node
identities to attach to the token. Applicable for Vault 1.11+ with Consul 1.8+.

* `consul_namespace` - (Optional) The Consul namespace that the token will be created in.
   Applicable for Vault 1.10+ and Consul 1.7+".

* `partition` - (Optional) The admin partition that the token will be created in.
   Applicable for Vault 1.10+ and Consul 1.11+".

* `max_ttl` - (Optional) Maximum TTL for leases associated with this role, in seconds.

* `ttl` - (Optional) Specifies the TTL for this role.

* `local` - (Optional) Indicates that the token should not be replicated globally and instead be local to the current datacenter.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Consul secret backend roles can be imported using the `backend`, `/roles/`, and the `name` e.g.

```
$ terraform import vault_consul_secret_backend_role.example consul/roles/my-role
```

## Note About Required Arguments
*At least one* of the four arguments `consul_policies`, `consul_roles`, `service_identities`, or
`node_identities` is required for a token. If desired, any combination of the four arguments up-to and
including all four, is valid.
