---
layout: "vault"
page_title: "Vault: vault_transit_secret_backend resource"
sidebar_current: "docs-vault-resource-transit-secret-backend"
description: |-
  Creates a transit secret backend for Vault.
---

# vault\_transit\_secret\_backend

Creates a transit Secret Backend for Vault. Transit secret backends can then perform cryptographic operations, once an encryption key has been added to
the backend.

## Example Usage

```hcl
resource "vault_transit_secret_backend" "transit" {
  path = "transit"
  description = "Example description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) The unique path this backend should be mounted at. Must not begin or end with a `/`.

* `description` - (Optional) A human-friendly description for this backend.

* `default_lease_ttl_seconds` - (Optional) The default TTL for credentials issued by this backend.

* `max_lease_ttl_seconds` - (Optional) The maximum TTL that can be requested for credentials issued by this backend.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Transit secret backends can be imported using the `path`, e.g.

```
$ terraform import vault_transit_secret_backend.transit transit
```
