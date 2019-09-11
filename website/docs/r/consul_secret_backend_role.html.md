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

resource vault_consul_secret_backend_role" "example" {
  name = "test-role"
  path = "${vault_consul_secret_backend.test.path}"

  policies = [
    "example-policy",
  ]
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) The unique of an existing Consul secrets backend mount. Must not begin or end with a `/`.

* `name` - (Required) The name of the Consul secrets engine role to create.

* `policies` - (Required) The list of Consul ACL policies to associate with these roles.

## Attributes Reference

No additional attributes are exported by this resource.
