---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_config_cluster resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-config-cluster"
description: |-
  Sets the cluster configuration on an PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_config\_cluster

Allows setting the cluster-local's API mount path and AIA distribution point on a particular performance replication cluster.

## Example Usage

```hcl
resource "vault_mount" "root" {
  path                      = "pki-root"
  type                      = "pki"
  description               = "root PKI"
  default_lease_ttl_seconds = 8640000
  max_lease_ttl_seconds     = 8640000
}

resource "vault_pki_secret_backend_config_cluster" "example" {
  backend  = vault_mount.root.path
  path     = "http://127.0.0.1:8200/v1/pki-root"
  aia_path = "http://127.0.0.1:8200/v1/pki-root"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Required) The path the PKI secret backend is mounted at, with no leading or trailing `/`s.

* `path` - (Required) Specifies the path to this performance replication cluster's API mount path.

* `aia_path` - (Required) Specifies the path to this performance replication cluster's AIA distribution point.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

The PKI config cluster can be imported using the resource's `id`. 
In the case of the example above the `id` would be `pki-root/config/cluster`, 
where the `pki-root` component is the resource's `backend`, e.g.

```
$ terraform import vault_pki_secret_backend_config_cluster.example pki-root/config/cluster
```
