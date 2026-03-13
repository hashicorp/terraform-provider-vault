---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_external_ca_order_challenge_fulfilled resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-external-ca-order-challenge-fulfilled"
description: |-
  Marks an ACME challenge as fulfilled for a specific identifier in an order.
---

# vault\_pki\_secret\_backend\_external\_ca\_order\_challenge\_fulfilled

Marks an ACME challenge as fulfilled for a specific identifier in an order. This resource notifies Vault that the challenge has been completed and the ACME server can now validate it.

~> **Note** This resource should be used after you have completed the challenge requirements (e.g., placed the HTTP-01 challenge file, created the DNS-01 TXT record, or configured the TLS-ALPN-01 certificate). Use the `vault_pki_secret_backend_external_ca_order_challenge` data source to retrieve the challenge details first.

## Example Usage with HTTP-01 Challenge

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
  allowed_domains_options = ["bare_domains", "subdomains"]
  allowed_challenge_types = ["http-01"]
}

resource "vault_pki_secret_backend_external_ca_order" "example" {
  mount     = vault_mount.pki.path
  role_name = vault_pki_secret_backend_external_ca_role.example.name
  
  identifiers = ["www.example.com"]
}

# Retrieve challenge details
data "vault_pki_secret_backend_external_ca_order_challenge" "example" {
  mount          = vault_mount.pki.path
  role_name      = vault_pki_secret_backend_external_ca_role.example.name
  order_id       = vault_pki_secret_backend_external_ca_order.example.order_id
  challenge_type = "http-01"
  identifier     = "www.example.com"
}

# Deploy the challenge (example using local_file)
resource "local_file" "challenge" {
  filename = "/var/www/html/.well-known/acme-challenge/${data.vault_pki_secret_backend_external_ca_order_challenge.example.token}"
  content  = data.vault_pki_secret_backend_external_ca_order_challenge.example.key_authorization
}

# Mark challenge as fulfilled after deployment
resource "vault_pki_secret_backend_external_ca_order_challenge_fulfilled" "example" {
  depends_on = [local_file.challenge]
  
  mount          = vault_mount.pki.path
  role_name      = vault_pki_secret_backend_external_ca_role.example.name
  order_id       = vault_pki_secret_backend_external_ca_order.example.order_id
  challenge_type = "http-01"
  identifier     = "www.example.com"
}
```

## Example Usage with DNS-01 Challenge

```hcl
# Retrieve DNS challenge details
data "vault_pki_secret_backend_external_ca_order_challenge" "dns" {
  mount          = vault_mount.pki.path
  role_name      = vault_pki_secret_backend_external_ca_role.example.name
  order_id       = vault_pki_secret_backend_external_ca_order.example.order_id
  challenge_type = "dns-01"
  identifier     = "www.example.com"
}

# Create DNS TXT record (example using AWS Route53)
resource "aws_route53_record" "acme_challenge" {
  zone_id = aws_route53_zone.example.zone_id
  name    = "_acme-challenge.www.example.com"
  type    = "TXT"
  ttl     = 60
  records = [data.vault_pki_secret_backend_external_ca_order_challenge.dns.key_authorization]
}

# Mark challenge as fulfilled
resource "vault_pki_secret_backend_external_ca_order_challenge_fulfilled" "dns" {
  depends_on = [aws_route53_record.acme_challenge]
  
  mount          = vault_mount.pki.path
  role_name      = vault_pki_secret_backend_external_ca_role.example.name
  order_id       = vault_pki_secret_backend_external_ca_order.example.order_id
  challenge_type = "dns-01"
  identifier     = "www.example.com"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `mount` - (Required) The path where the PKI External CA secret backend is mounted.

* `role_name` - (Required) Name of the role associated with the order.

* `order_id` - (Required) The unique identifier for the ACME order.

* `challenge_type` - (Required) The type of ACME challenge that was fulfilled. Valid values are `http-01`, `dns-01`, `tls-alpn-01`.

* `identifier` - (Required) The identifier (domain name) for which the challenge was fulfilled.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `id` - The ID of the resource in the format `<mount>/role/<role_name>/order/<order_id>/fulfilled-challenge/<challenge_type>/<identifier>`.

## Import

PKI External CA order challenge fulfilled resources can be imported using the format `<mount>/role/<role_name>/order/<order_id>/fulfilled-challenge/<challenge_type>/<identifier>`, e.g.

```
$ terraform import vault_pki_secret_backend_external_ca_order_challenge_fulfilled.example pki/role/example-role/order/abc123/fulfilled-challenge/http-01/www.example.com
```

~> **Note** This resource represents an action (marking a challenge as fulfilled) rather than a persistent object. Deletion removes it from state without making any API calls, as the action cannot be undone.