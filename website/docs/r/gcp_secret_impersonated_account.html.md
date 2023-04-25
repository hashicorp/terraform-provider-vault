---
layout: "vault"
page_title: "Vault: vault_gcp_secret_impersonated_account resource"
sidebar_current: "docs-vault-resource-gcp-secret-impersonated-account"
description: |-
  Creates a Impersonated Account for the GCP Secret Backend for Vault.
---

# vault\_gcp\_secret\_impersonated\_account

Creates a Impersonated Account in the [GCP Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html) for Vault.

Each [impersonated account](https://www.vaultproject.io/docs/secrets/gcp/index.html#impersonated-accounts) is tied to a separately managed
Service Account.

## Example Usage

```hcl
resource "google_service_account" "this" {
  account_id = "my-awesome-account"
}

resource "vault_gcp_secret_backend" "gcp" {
  path        = "gcp"
  credentials = "${file("credentials.json")}"
}

resource "vault_gcp_secret_impersonated_account" "impersonated_account" {
  backend        = vault_gcp_secret_backend.gcp.path

  impersonated_account  = "this"
  service_account_email = google_service_account.this.email
  token_scopes          = ["https://www.googleapis.com/auth/cloud-platform"]
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required, Forces new resource) Path where the GCP Secrets Engine is mounted

* `impersonated_account` - (Required, Forces new resource) Name of the Impersonated Account to create

* `service_account_email` - (Required, Forces new resource) Email of the GCP service account to impersonate.

* `token_scopes` - (Required) List of OAuth scopes to assign to access tokens generated under this impersonated account.

## Attributes Reference

In addition to the fields above, the following attributes are also exposed:

* `service_account_project` - Project the service account belongs to.

## Import

A impersonated account can be imported using its Vault Path. For example, referencing the example above,

```
$ terraform import vault_gcp_secret_impersonated_account.impersonated_account gcp/impersonated-account/project_viewer
```
