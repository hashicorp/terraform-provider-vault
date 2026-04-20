---
layout: "vault"
page_title: "Vault: ephemeral vault_gcp_service_account_key resource"
sidebar_current: "docs-vault-ephemeral-gcp-service-account-key"
description: |-
  Generate ephemeral GCP service account keys from Vault

---

# vault\_gcp\_service\_account\_key

Generates ephemeral GCP service account keys from the Vault GCP Secrets engine that are not stored in the remote TF state.
For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/docs/secrets/gcp)
for the GCP Secrets engine.

## Example Usage

### Using with a Roleset

```hcl
resource "vault_gcp_secret_backend" "gcp" {
  path        = "gcp"
  credentials = file("credentials.json")
}

resource "vault_gcp_secret_roleset" "roleset" {
  backend      = vault_gcp_secret_backend.gcp.path
  roleset      = "project_viewer"
  secret_type  = "service_account_key"
  project      = "my-awesome-project"
  
  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/my-awesome-project"
    roles    = ["roles/viewer"]
  }
}

ephemeral "vault_gcp_service_account_key" "key" {
  mount   = vault_gcp_secret_backend.gcp.path
  roleset = vault_gcp_secret_roleset.roleset.roleset
}

output "service_account_email" {
  value     = ephemeral.vault_gcp_service_account_key.key.service_account_email
  sensitive = true
}
```

### Using with a Static Account

```hcl
resource "vault_gcp_secret_backend" "gcp" {
  path        = "gcp"
  credentials = file("credentials.json")
}

resource "vault_gcp_secret_static_account" "static" {
  backend               = vault_gcp_secret_backend.gcp.path
  static_account        = "static-account"
  secret_type           = "service_account_key"
  service_account_email = "vault-tester@my-project.iam.gserviceaccount.com"
  
  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/my-awesome-project"
    roles    = ["roles/viewer"]
  }
}

ephemeral "vault_gcp_service_account_key" "key" {
  mount          = vault_gcp_secret_backend.gcp.path
  static_account = vault_gcp_secret_static_account.static.static_account
}
```

## Argument Reference

The following arguments are supported:

* `mount` - (Required) Path where the GCP secrets engine is mounted in Vault.

* `roleset` - (Optional) Name of the GCP roleset to generate credentials for. Mutually exclusive with `static_account`.

* `static_account` - (Optional) Name of the GCP static account to generate credentials for. Mutually exclusive with `roleset`.

* `key_algorithm` - (Optional) Key algorithm used to generate the key. Defaults to 2k RSA key. 
  Accepted values: `KEY_ALG_UNSPECIFIED`, `KEY_ALG_RSA_1024`, `KEY_ALG_RSA_2048`.

* `key_type` - (Optional) Private key type to generate. Defaults to JSON credentials file.
  Accepted values: `TYPE_UNSPECIFIED`, `TYPE_PKCS12_FILE`, `TYPE_GOOGLE_CREDENTIALS_FILE`.

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
  *Available only for Vault Enterprise*.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `private_key_data` - The private key data in JSON format (base64 encoded for PKCS12 format).

* `private_key_type` - The type of the private key that was generated.

* `service_account_email` - The email address of the service account (extracted from the key data when available).

* `lease_id` - Lease identifier assigned by Vault.

* `lease_duration` - Lease duration in seconds relative to the time in `lease_start_time`.

* `lease_start_time` - Time at which the lease was read, using the clock of the system where Terraform was running.

* `lease_renewable` - True if the duration of this lease can be extended through renewal.

## Required Vault Capabilities

Use of this resource requires the `create` or `update` capability on the given path.