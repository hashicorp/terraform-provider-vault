---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend resource"
sidebar_current: "docs-vault-resource-pki-secret-backend"
description: |-
  Creates an PKI secret backend for Vault.
---

# vault\_pki\_secret\_backend

Creates an PKI Secret Backend for Vault. PKI secret backends can then issue certificates, once a role has been added to
the backend.

## Example Usage

```hcl
resource "vault_pki_secret_backend" "pki" {
  path                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
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

PKI secret backends can be imported using the `path`, e.g.

```
$ terraform import vault_pki_secret_backend.pki pki
```
