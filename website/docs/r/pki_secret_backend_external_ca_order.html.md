---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_external_ca_order resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-external-ca-order"
description: |-
  Creates and manages ACME orders for certificate issuance via PKI External CA roles.
---

# vault\_pki\_secret\_backend\_external\_ca\_order

Creates and manages ACME orders for certificate issuance via PKI External CA roles. This resource initiates the ACME certificate order process with an external Certificate Authority.

~> **Note** This resource creates an ACME order but does not automatically fulfill challenges or fetch the certificate. Use `vault_pki_secret_backend_external_ca_order_challenge` data source to retrieve challenge details, `vault_pki_secret_backend_external_ca_order_challenge_fulfilled` to mark challenges as fulfilled, and `vault_pki_secret_backend_external_ca_order_certificate` to fetch the final certificate.

## Example Usage with Identifiers

```hcl
resource "vault_mount" "pki" {
  path = "pki"
  type = "pki"
}

resource "vault_pki_secret_backend_acme_account" "example" {
  mount         = vault_mount.pki.path
  name          = "my-acme-account"
  directory_url = "https://acme-v02.api.letsencrypt.org/directory"
  email_contacts = [
    "admin@example.com"
  ]
}

resource "vault_pki_secret_backend_external_ca_role" "example" {
  mount             = vault_mount.pki.path
  name              = "example-role"
  acme_account_name = vault_pki_secret_backend_acme_account.example.name
  
  allowed_domains = ["example.com"]
  allowed_domain_options = ["bare_domains", "subdomains"]
}

resource "vault_pki_secret_backend_external_ca_order" "example" {
  mount     = vault_mount.pki.path
  role_name = vault_pki_secret_backend_external_ca_role.example.name
  
  identifiers = [
    "www.example.com",
    "api.example.com"
  ]
}
```

## Example Usage with CSR

```hcl
resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "example" {
  private_key_pem = tls_private_key.example.private_key_pem

  subject {
    common_name = "www.example.com"
  }

  dns_names = [
    "www.example.com",
    "api.example.com"
  ]
}

resource "vault_pki_secret_backend_external_ca_order" "with_csr" {
  mount     = vault_mount.pki.path
  role_name = vault_pki_secret_backend_external_ca_role.example.name
  
  csr = tls_cert_request.example.cert_request_pem
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `mount` - (Required) The path where the PKI External CA secret backend is mounted.

* `role_name` - (Required) Name of the role to create the order for.

* `identifiers` - (Optional) List of identifiers (domain names) for the certificate order. Required if `csr` is not provided. Mutually exclusive with `csr`.

* `csr` - (Optional) PEM-encoded Certificate Signing Request containing identifiers. Required if `identifiers` is not provided. Mutually exclusive with `identifiers`.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `id` - The ID of the resource in the format `<mount>/role/<role_name>/order/<order_id>`.

* `order_id` - The unique identifier for this ACME order.

* `order_status` - Current status of the order. Possible values include:
  - `new` - Order has been created
  - `submitted` - Order has been submitted to the ACME server
  - `awaiting-challenge-fulfillment` - Waiting for challenges to be fulfilled
  - `completed` - Certificate has been issued
  - `error` - An error occurred during processing
  - `expired` - Order has expired
  - `revoked` - Order has been revoked

* `creation_date` - The date and time the order was created in RFC3339 format.

* `next_work_date` - The next scheduled work date for this order in RFC3339 format.

* `last_update` - The date and time the order was last updated in RFC3339 format.

* `last_error` - The last error message encountered during order processing, if any.

* `serial_number` - The serial number of the issued certificate (available when order is completed).

* `expires` - The expiration date of the order in RFC3339 format.

* `challenges` - Map of identifiers to their ACME challenges (simplified representation).

## Import

PKI External CA orders can be imported using the format `<mount>/role/<role_name>/order/<order_id>`, e.g.

```
$ terraform import vault_pki_secret_backend_external_ca_order.example pki/role/example-role/order/abc123
```

~> **Note** Orders are immutable once created. Any changes to the configuration will require creating a new order.