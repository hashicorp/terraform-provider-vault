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
    credentials  = "${file("vault-gcp-credentials.json")}"
}
```

## Argument Reference

The following arguments are supported:

* `credentials` - (Required) A JSON string containing the contents of a GCP credentials file.

For more details on the usage of each argument consult the [Vault GCP API documentation](https://www.vaultproject.io/api/auth/gcp/index.html#configure).

## Attribute Reference

In addition to the fields above, the following attributes are also exposed:

* `client_id` - The Client ID of the credentials

* `private_key_id` - The ID of the private key from the credentials

* `project_id` - The GCP Project ID

* `client_email` - The clients email assosiated with the credentials
