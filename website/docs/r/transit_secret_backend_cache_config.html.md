---
layout: "vault"
page_title: "Vault: vault_transit_secret_cache_config resource"
sidebar_current: "docs-vault-resource-transit-secret-cache-config"
description: |-
  Configure the cache for the Transit Secret Backend in Vault.
---

# vault\_transit\_secret\_cache\_config

Configure the cache for the Transit Secret Backend in Vault.

## Example Usage

```hcl
resource "vault_mount" "transit" {
  path                      = "transit"
  type                      = "transit"
  description               = "Example description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_transit_secret_cache_config" "cfg" {
  backend = vault_mount.transit.path
  size    = 500
}

```
## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Required) The path the transit secret backend is mounted at, with no leading or trailing `/`s.

* `size` - (Required) The number of cache entries. 0 means unlimited.


## Attributes Reference

No additional attributes are exported by this resource.
