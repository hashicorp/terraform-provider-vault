---
layout: "vault"
page_title: "Use ephemeral resources in the Terraform Vault Provider"
sidebar_current: "docs-use-ephemeral-resources-in-the-vault-provider"
description: |-
  Use ephemeral resources in the Terraform Vault Provider

---

# Ephemeral Resources in the Vault provider

Ephemeral resources are Terraform resources that are essentially temporary. They allow users to access
and use data in their configurations without that data being stored in Terraform state.

Ephemeral resources are available in Terraform v1.10 and later. For more information, see the 
[official HashiCorp documentation for Ephemeral Resources](https://developer.hashicorp.com/terraform/language/resources/ephemeral).

To mark the launch of the ephemeral resources feature, the Vault provider has added two ephemeral resources:
- [`vault_kv_secret_v2`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/ephemeral-resources/kv_secret_v2)
- [`vault_database_secret`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/ephemeral-resources/database_secret)

`vault_kv_secret_v2` is based on an existing data sources already in the provider. Going forward
you may wish to update your configurations to use these ephemeral versions, as they will allow you
to avoid storing credentials and secret values in your Terraform state.

## Use the Vault provider's new ephemeral resources

Ephemeral resources are a source of ephemeral data, and they can be referenced in your
configuration just like the attributes of resources and data sources. However, a field that
references an ephemeral resource must be capable of handling ephemeral data. Due to this, resources
in the Vault provider will need to be updated so they include write-only attributes that are
capable of using ephemeral data while not storing those values in the resource's state.

For the launch of ephemeral resources in `5.X`, three write-only parameters have been added.
Please refer to the [using write-only attributes](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/guides/using_write_only_attributes)
page for more details on using the parameters. Apart from these, ephemeral resources can also be used
to pass values into provider configuration blocks, which are already capable of receiving ephemeral values.

The following sections show two examples from the new ephemeral resources' documentation pages, which demonstrate
how to use and test out the ephemeral resources in their current form.


### Opt to defer provisioning an ephemeral resource until `terraform apply` using the `mount_id` parameter

The [documentation](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/ephemeral-resources/kv_secret_v2)
for the `vault_kv_secret_v2` ephemeral resource has a simple example that you can use to view how ephemeral resources
in the Vault provider can always choose to defer provisioning until `terraform apply` using the `mount_id` parameter.
The value for `mount_id` should be the set to the ID of the `vault_mount` resource being referenced:

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

ephemeral "vault_kvv2_secret" "db_secret" {
  mount = vault_mount.kvv2.path
  name = vault_kv_secret_v2.db_root.name
  mount_id = vault_mount.kvv2.id
}
```

During `terraform plan`, the ephemeral resource depends on the unknown value `mount_id`, which will
be known only after `vault_mount` has been created. Hence, you will see that the ephemeral resource
is deferred until the apply step:

```
ephemeral.vault_kvv2_secret.db_secret: Configuration unknown, deferring...

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # vault_kv_secret_v2.db_root will be created
  + resource "vault_kv_secret_v2" "db_root" {
      + data_json_wo         = (write-only attribute)
      + data_json_wo_version = 1
    ...
```

During `terrform apply` you will see the ephemeral resource is the final resource to be evaluated, because
it depends on the two other resources, and the ephemeral resource is not reflected in the statistics
about how many resources were created during the apply action:

```
vault_mount.kvv2: Creating...
vault_mount.kvv2: Creation complete after 0s [id=my-kvv2]
vault_kv_secret_v2.db_root: Creating...
vault_kv_secret_v2.db_root: Creation complete after 0s [id=my-kvv2/data/pgx-user]
ephemeral.vault_kvv2_secret.db_secret: Opening...
ephemeral.vault_kvv2_secret.db_secret: Opening complete after 0s
ephemeral.vault_kvv2_secret.db_secret: Closing...
ephemeral.vault_kvv2_secret.db_secret: Closing complete after 0s

Apply complete! Resources: 2 added, 0 changed, 0 destroyed
```

If you run the example using a local Vault server you can also inspect the state, where you will
see that the ephemeral resource is not represented.

Note that `mount_id` is only used to defer the provisioning of the ephemeral resource. 
If the provisioning of the resource does not need to be deferred to the apply stage, `mount_id` may
be omitted from the configuration:

```hcl
ephemeral "vault_kvv2_secret" "db_secret" {
  mount = vault_mount.kvv2.path
  name = vault_kv_secret_v2.db_root.name
}
```


### Use ephemeral resources to securely configure secrets and databases in the Vault provider

The new ephemeral resources may be used to securely obtain secret/credential data from Vault
in order to configure other resources or providers:

```hcl
provider "vault" {
}

# Securely obtain an already provisioned secret from Vault
ephemeral "vault_kvv2_secret" "db_secret" {
  mount = "my-kvv2"
  name = "pgx-root"
}

# Enable database secrets engine
resource "vault_mount" "db" {
  path = "postgres"
  type = "database"
}

# Configure a secure Postgres connection using ephemeral resource and write-only attributes
resource "vault_database_secret_backend_connection" "postgres" {
  backend       = vault_mount.db.path
  name          = "postrgres-db"
  allowed_roles = ["pgx-role"]

  postgresql {
    connection_url = "postgresql://{{username}}:{{password}}@localhost:5432/postgres"
    username = "postgres"
    password_wo = tostring(ephemeral.vault_kvv2_secret.db_secret.data.password)
    password_wo_version = 1
  }
}

# Create a role to generate Postgres DB credentials
resource "vault_database_secret_backend_role" "role" {
  backend             = vault_mount.db.path
  name                = "pgx-role"
  db_name             = vault_database_secret_backend_connection.postgres.name
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
  ]
}

# Securely obtain database credentials using ephemeral resource
ephemeral "vault_db_secret" "db_user_credentials" {
  mount = vault_mount.db.path
  name = vault_database_secret_backend_role.role.name
  mount_id = vault_mount.db.id
}
```