---
layout: "vault"
page_title: "Vault: ephemeral vault_gcp_oauth2_access_token resource"
sidebar_current: "docs-vault-ephemeral-gcp-oauth2-access-token"
description: |-
  Generate ephemeral GCP OAuth2 access tokens from Vault

---

# vault\_gcp\_oauth2\_access\_token

Generates ephemeral GCP OAuth2 access tokens from the Vault GCP Secrets engine that are not stored in the remote TF state.
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
  secret_type  = "access_token"
  project      = "my-awesome-project"
  
  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/my-awesome-project"
    roles    = ["roles/viewer"]
  }
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount   = vault_gcp_secret_backend.gcp.path
  roleset = vault_gcp_secret_roleset.roleset.roleset
}

output "service_account_email" {
  value     = ephemeral.vault_gcp_oauth2_access_token.token.service_account_email
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
  secret_type           = "access_token"
  service_account_email = "vault-tester@my-project.iam.gserviceaccount.com"
  
  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/my-awesome-project"
    roles    = ["roles/viewer"]
  }
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount          = vault_gcp_secret_backend.gcp.path
  static_account = vault_gcp_secret_static_account.static.static_account
}
```

### Using with an Impersonated Account

```hcl
resource "vault_gcp_secret_backend" "gcp" {
  path        = "gcp"
  credentials = file("credentials.json")
}

resource "vault_gcp_secret_impersonated_account" "impersonated" {
  backend               = vault_gcp_secret_backend.gcp.path
  impersonated_account  = "impersonated-account"
  service_account_email = "vault-tester@my-project.iam.gserviceaccount.com"
  token_scopes          = ["https://www.googleapis.com/auth/cloud-platform"]
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount                = vault_gcp_secret_backend.gcp.path
  impersonated_account = vault_gcp_secret_impersonated_account.impersonated.impersonated_account
}
```

## Argument Reference

The following arguments are supported:

* `mount` - (Required) Path where the GCP secrets engine is mounted in Vault.

* `roleset` - (Optional) Name of the GCP roleset to generate OAuth2 access token for. Mutually exclusive with `static_account` and `impersonated_account`.

* `static_account` - (Optional) Name of the GCP static account to generate OAuth2 access token for. Mutually exclusive with `roleset` and `impersonated_account`.

* `impersonated_account` - (Optional) Name of the GCP impersonated account to generate OAuth2 access token for. Mutually exclusive with `roleset` and `static_account`.

* `max_retries` - (Optional) Maximum number of retries when the GCP service account or key is not yet ready. Each retry waits 1 second. Defaults to `10`.

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](../index.html#namespace).
  *Available only for Vault Enterprise*.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `token` - The OAuth2 access token.

* `token_ttl` - The TTL of the token in seconds.

* `service_account_email` - The email address of the service account.

* `lease_id` - Lease identifier assigned by Vault.

* `lease_duration` - Lease duration in seconds relative to the time in `lease_start_time`.

* `lease_start_time` - Time at which the lease was read, using the clock of the system where Terraform was running.

* `lease_renewable` - True if the duration of this lease can be extended through renewal.

## Required Vault Capabilities

Use of this resource requires the `read` capability on the given path.