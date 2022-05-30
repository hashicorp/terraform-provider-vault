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
}
```

## Argument Reference

The following arguments are supported:

* `credentials` - A JSON string containing the contents of a GCP credentials file. If this value is empty, Vault will try to use Application Default Credentials from the machine on which the Vault server is running.

* `path` - (Optional) The path to mount the auth method — this defaults to 'gcp'.

* `description` - (Optional) A description of the auth method.

* `local` - (Optional) Specifies if the auth method is local only.

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
