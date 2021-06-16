---
layout: "vault"
page_title: "Vault: vault_gcp_secret_roleset resource"
sidebar_current: "docs-vault-resource-gcp-secret-roleset"
description: |-
  Creates a Roleset for the GCP Secret Backend for Vault.
---

# vault\_gcp\_secret\_roleset

Creates a Roleset in the [GCP Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html) for Vault.

Each Roleset is [tied](https://www.vaultproject.io/docs/secrets/gcp/index.html#service-accounts-are-tied-to-rolesets) to a Service Account, and can have one or more [bindings](https://www.vaultproject.io/docs/secrets/gcp/index.html#roleset-bindings) associated with it.

## Example Usage

```hcl
locals {
  project = "my-awesome-project"
}

resource "vault_gcp_secret_backend" "gcp" {
  path        = "gcp"
  credentials = "${file("credentials.json")}"
}

resource "vault_gcp_secret_roleset" "roleset" {
  backend      = vault_gcp_secret_backend.gcp.path
  roleset      = "project_viewer"
  secret_type  = "access_token"
  project      = local.project
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/${local.project}"

    roles = [
      "roles/viewer",
    ]
  }
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required, Forces new resource) Path where the GCP Secrets Engine is mounted

* `roleset` - (Required, Forces new resource) Name of the Roleset to create

* `project` - (Required, Forces new resource) Name of the GCP project that this roleset's service account will belong to.

* `secret_type` - (Optional, Forces new resource) Type of secret generated for this role set. Accepted values: `access_token`, `service_account_key`. Defaults to `access_token`.

* `token_scopes` - (Optional, Required for `secret_type = "access_token"`) List of OAuth scopes to assign to `access_token` secrets generated under this role set (`access_token` role sets only).

* `binding` - (Required) Bindings to create for this roleset. This can be specified multiple times for multiple bindings. Structure is documented below.

The `binding` block supports:

* `resource` - (Required) Resource or resource path for which IAM policy information will be bound. The resource path may be specified in a few different [formats](https://www.vaultproject.io/docs/secrets/gcp/index.html#roleset-bindings).

* `roles` - (Required) List of [GCP IAM roles](https://cloud.google.com/iam/docs/understanding-roles) for the resource.

## Attributes Reference

In addition to the fields above, the following attributes are also exposed:

* `service_account_email` Email of the service account created by Vault for this Roleset.

## Import

A roleset can be imported using its Vault Path. For example, referencing the example above,

```
$ terraform import vault_gcp_secret_roleset.roleset gcp/roleset/project_viewer
```
