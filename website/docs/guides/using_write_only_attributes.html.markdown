---
layout: "vault"
page_title: "Use write-only attributes in the Terraform Vault Provider"
sidebar_current: "docs-use-write-only-attributes-in-the-vault-provider"
description: |-
  Use write-only attributes in the Terraform Vault Provider

---

# Write-only attributes in the Vault provider


The Vault provider has introduced new write-only attributes (supported from Terraform `v1.11+`) for a more secure way to manage data.
The new `WriteOnly` attribute accepts values from configuration and will not be stored in plan or state
providing an additional layer of security and control over data access.

For more information, see the [official HashiCorp documentation for Write-only Attributes](https://developer.hashicorp.com/terraform/plugin/sdkv2/resources/write-only-arguments).

To mark the launch of the feature in `5.X`, the Vault provider has added the following write-only attributes:
- [`vault_kv_secret_v2: data_json_wo`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/kv_secret_v2#data_json_wo-1)
- [`vault_database_secret_backend_connection_: password_wo`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/database_secret_backend_connection#password_wo-1)
- [`vault_gcp_secret_backend: credentials_wo`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/gcp_secret_backend#credentials_wo-1)

These were chosen due to them being marked as sensitive already in the provider. Although sensitive attributes
do not appear in `terraform plan`, they are still stored in the Terraform state. Write-only attributes
allow users to access and use data in their configurations without that data being stored in Terraform state.

Going forward  you may wish to update your configurations to use these write-only attributes, as they will allow
you to avoid storing credentials and secret values in your Terraform state.

## Use the Vault provider's new write-only attributes

The following sections show how to use the new write-only attributes in the Vault provider.

### Applying a write-only attribute

The following example shows how to apply a write-only attribute. All write-only attributes are marked
with the `wo` suffix and can not be used with the attribute that it's mirroring.
For example, `data_json_wo` can not be used with `data_json`. A write-only parameter must always
be supplied with the attribute's version parameter, marked with the `wo_version` suffix:

```hcl
resource "vault_mount" "kvv2" {
  path        = "my-kvv2"
  type        = "kv"
  options     = { version = "2" }
}

resource "vault_kv_secret_v2" "db_root" {
  mount                      = vault_mount.kvv2.path
  name                       = "pgx-root"
  data_json_wo                  = jsonencode(
    {
      password       = "root-user-password"
    }
  )
  data_json_wo_version = 1
}
```

During `terraform plan` you will see that the write-only attribute is marked appropriately:

```
  # vault_kv_secret_v2.db_root will be created
  + resource "vault_kv_secret_v2" "db_root" {
      + data                 = (sensitive value)
      + data_json_wo         = (write-only attribute)
      + data_json_wo_version = 1
      + delete_all_versions  = false
      + disable_read         = false
      + id                   = (known after apply)
      + metadata             = (known after apply)
      + mount                = "my-kvv2"
      + name                 = "pgx-user"
      + path                 = (known after apply)
    }

```

Upon `terrform apply` you will see in `terraform.tfstate` that the write-only attribute from the configuration is not reflected in the state:

```
    ...
    "mode": "managed",
    "type": "vault_kv_secret_v2",
    "name": "db_root",
    "provider": "provider[\"registry.terraform.io/hashicorp/vault\"]",
    "instances": [
    {
    "schema_version": 0,
    "attributes": {
    "cas": null,
    "custom_metadata": [
        {
            "cas_required": false,
            "data": {},
            "delete_version_after": 0,
            "max_versions": 0
        }
    ],
    "data": {},
    "data_json": null,
    "data_json_wo": null,
    "data_json_wo_version": 1,
    "delete_all_versions": false,
    "disable_read": false,
    "id": "my-kvv2/data/pgx-user",
    ...
    }
```

Any value that is set for a write-only attribute is nulled out before the RPC response is sent to Terraform.

### Updating write-only attributes

Since write-only attributes are not stored in the Terraform state, they cannot be updated by just changing the value in the configuration due to the attribute being nulled out.

In order to update a write-only attribute we must change the write-only attribute's version.

```hcl
resource "vault_kv_secret_v2" "db_root" {
  mount                      = vault_mount.kvv2.path
  name                       = "pgx-root"
  data_json_wo                  = jsonencode(
    {
      password       = "root-user-password-updated" // updated secret data
    }
  )
  data_json_wo_version = 2 // updated data version
}
```

A `terraform apply` of this configuration will allow you to update the write-only attribute despite the new value not being shown in the plan.

```
Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  ~ update in-place

Terraform will perform the following actions:

  # vault_kv_secret_v2.db_root will be updated in-place
  ~ resource "vault_kv_secret_v2" "db_root" {
      ~ data_json_wo_version = 1 -> 2
        id                   = "my-kvv2/data/pgx-root"
        name                 = "pgx-root"
        # (7 unchanged attributes hidden)

        # (1 unchanged block hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.
```