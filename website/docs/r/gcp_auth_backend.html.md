---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-gcp-auth-backend-role"
description: |-
  Managing roles in an GCP auth backend in Vault
---

# vault\_gcp\_auth\_backend

Provides a resource to configure the [GCP auth backend within Vault](https://www.vaultproject.io/docs/auth/gcp.html).

## Example Usage

```hcl
resource "vault_gcp_auth_backend" "gcp" { 
  credentials  = file("vault-gcp-credentials.json")

  custom_endpoint = {
    api     = "www.googleapis.com"
    iam     = "iam.googleapis.com"
    crm     = "cloudresourcemanager.googleapis.com"
    compute = "compute.googleapis.com"
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `credentials` - A JSON string containing the contents of a GCP credentials file. If this value is empty, Vault will try to use Application Default Credentials from the machine on which the Vault server is running.

* `path` - (Optional) The path to mount the auth method — this defaults to 'gcp'.

* `disable_remount` - (Optional) If set, opts out of mount migration on path updates.
  See here for more info on [Mount Migration](https://www.vaultproject.io/docs/concepts/mount-migration)

* `description` - (Optional) A description of the auth method.

* `local` - (Optional) Specifies if the auth method is local only.

* `custom_endpoint` - (Optional) Specifies overrides to
  [service endpoints](https://cloud.google.com/apis/design/glossary#api_service_endpoint)
  used when making API requests. This allows specific requests made during authentication
  to target alternative service endpoints for use in [Private Google Access](https://cloud.google.com/vpc/docs/configure-private-google-access)
  environments. Requires Vault 1.11+.

  Overrides are set at the subdomain level using the following keys:
  - `api` - Replaces the service endpoint used in API requests to `https://www.googleapis.com`.
  - `iam` - Replaces the service endpoint used in API requests to `https://iam.googleapis.com`.
  - `crm` - Replaces the service endpoint used in API requests to `https://cloudresourcemanager.googleapis.com`.
  - `compute` - Replaces the service endpoint used in API requests to `https://compute.googleapis.com`.

  The endpoint value provided for a given key has the form of `scheme://host:port`.
  The `scheme://` and `:port` portions of the endpoint value are optional.

For more details on the usage of each argument consult the [Vault GCP API documentation](https://www.vaultproject.io/api-docs/auth/gcp#configure).

## Attribute Reference

In addition to the fields above, the following attributes are also exposed:

* `client_id` - The Client ID of the credentials

* `private_key_id` - The ID of the private key from the credentials

* `project_id` - The GCP Project ID

* `client_email` - The clients email associated with the credentials

## Import

GCP authentication backends can be imported using the backend name, e.g.

```
$ terraform import vault_gcp_auth_backend.gcp gcp
```
