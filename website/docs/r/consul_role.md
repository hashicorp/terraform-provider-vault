---
layout: "vault"
page_title: "Vault: vault_consul_role resource"
sidebar_current: "docs-vault-consul-role"
description: |-
  Writes arbitrary consul roles for Vault
---

# vault\_consul\_role


## Example Usage

```hcl
resource "vault_consul_role" "example" {
  name = "app"
  path = "consul/roles"
  role = <<EOT
key "app/" {
    policy = "read"
}
key "vault/" {
    policy = "deny"
}
EOT
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the role

* `role` - (Required) String containing the role's data

* `path` - (Optional) The path you wish the role to be placed in. Default is ```consul/roles```

## Attributes Reference

No additional attributes are exported by this resource.
