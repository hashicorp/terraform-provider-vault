---
layout: "vault"
page_title: "Vault: ephemeral vault_generic_secret resource"
sidebar_current: "docs-vault-ephemeral-generic-secret"
description: |-
  Read ephemeral secrets from arbitrary paths in Vault

---

# vault_generic_secret (Ephemeral)

Reads ephemeral data from a given path in Vault. These secrets are not stored in Terraform state and are automatically managed by Vault.

This ephemeral resource is primarily intended to be used with
[Vault's KV secret backend](https://developer.hashicorp.com/vault/docs/secrets/kv),
but it is also compatible with any other Vault endpoint that supports
the `vault read` command.

~> **Important** Ephemeral resources are designed for sensitive data that should not be stored in Terraform state. However, the data will still appear in console output when Terraform runs and may be included in plan files if secrets are interpolated into resource attributes. Protect these artifacts accordingly.

## Example Usage

### KV Version 1

```hcl
resource "vault_mount" "kvv1" {
  path = "kvv1"
  type = "kv"
  options = {
    version = "1"
  }
}

resource "vault_generic_secret" "example" {
  path = "${vault_mount.kvv1.path}/secret"
  data_json = jsonencode({
    username = "admin"
    password = "secret123"
  })
}

ephemeral "vault_generic_secret" "example" {
  path = "${vault_mount.kvv1.path}/secret"
}

# Use the ephemeral secret in a provider configuration
provider "external_service" {
  username = ephemeral.vault_generic_secret.example.data["username"]
  password = ephemeral.vault_generic_secret.example.data["password"]
}
```

### KV Version 2

```hcl
resource "vault_mount" "kvv2" {
  path = "kvv2"
  type = "kv"
  options = {
    version = "2"
  }
}

resource "vault_kv_secret_v2" "example" {
  mount = vault_mount.kvv2.path
  name  = "creds"
  data_json = jsonencode({
    api_key = "my-api-key"
    region  = "us-west-2"
  })
}

ephemeral "vault_generic_secret" "example" {
  path = "${vault_mount.kvv2.path}/data/${vault_kv_secret_v2.example.name}"
}

# Access the ephemeral secret data
output "api_key" {
  value     = ephemeral.vault_generic_secret.example.data["api_key"]
  sensitive = true
}
```

### Reading a Specific Version

```hcl
resource "vault_mount" "kvv2" {
  path = "kvv2"
  type = "kv"
  options = {
    version = "2"
  }
}

resource "vault_kv_secret_v2" "example" {
  mount = vault_mount.kvv2.path
  name  = "app-secret"
  data_json = jsonencode({
    config = "v2-config"
  })
}

ephemeral "vault_generic_secret" "example" {
  path    = "${vault_mount.kvv2.path}/data/${vault_kv_secret_v2.example.name}"
  version = 1  # Read version 1 of the secret
}
```

### With Lease Start Time

```hcl
ephemeral "vault_generic_secret" "example" {
  path                  = "secret/data/app"
  with_lease_start_time = true
}

# Access lease information
output "lease_start" {
  value = ephemeral.vault_generic_secret.example.lease_start_time
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's
  configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `path` - (Required) Full path from which a secret will be read.
  For KV v1 secrets engines, this is typically `<mount>/secret-name`.
  For KV v2 secrets engines, this should be `<mount>/data/secret-name`.

* `version` - (Optional) Version of the secret to retrieve. This is used by the
  Vault KV secrets engine - version 2 to indicate which version of the secret
  to read. Use `-1` for the latest version.

* `with_lease_start_time` - (Optional) If set to true, stores `lease_start_time` 
  in the result. This represents the time at which the lease was read, using the 
  clock of the system where Terraform was running.

## Required Vault Capabilities

Use of this resource requires the `read` capability on the given path.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `data_json` - JSON-encoded secret data read from Vault. A string containing 
  the full data payload retrieved from Vault, serialized in JSON format.

* `data` - Map of strings read from Vault. A mapping whose keys are the top-level 
  data keys returned from Vault and whose values are the corresponding values. 
  This map can only represent string data, so any non-string values returned from 
  Vault are serialized as JSON.

* `lease_id` - Lease identifier assigned by Vault.

* `lease_duration` - Lease duration in seconds relative to `lease_start_time`.

* `lease_start_time` - Time at which the lease was acquired, using the system 
  clock where Terraform was running. Only populated when `with_lease_start_time` 
  is set to true.

* `lease_renewable` - True if the lease duration can be extended through renewal.
