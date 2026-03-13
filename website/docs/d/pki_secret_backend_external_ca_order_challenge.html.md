---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_external_ca_order_challenge data source"
sidebar_current: "docs-vault-datasource-pki-secret-backend-external-ca-order-challenge"
description: |-
  Retrieves ACME challenge details for a specific identifier in an order.
---

# vault\_pki\_secret\_backend\_external\_ca\_order\_challenge

Retrieves ACME challenge details for a specific identifier in an order. This data source provides the information needed to fulfill ACME challenges (HTTP-01, DNS-01, or TLS-ALPN-01) for domain validation.

~> **Note** This data source will poll the order status until it reaches the `awaiting-challenge-fulfillment` or `completed` state. Use this data source after creating an order with `vault_pki_secret_backend_external_ca_order`.

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

# Retrieve HTTP-01 challenge details
data "vault_pki_secret_backend_external_ca_order_challenge" "http" {
  mount          = vault_mount.pki.path
  role_name      = vault_pki_secret_backend_external_ca_role.example.name
  order_id       = vault_pki_secret_backend_external_ca_order.example.order_id
  challenge_type = "http-01"
  identifier     = "www.example.com"
}

# Deploy the challenge file
resource "local_file" "acme_challenge" {
  filename = "/var/www/html/.well-known/acme-challenge/${data.vault_pki_secret_backend_external_ca_order_challenge.http.token}"
  content  = data.vault_pki_secret_backend_external_ca_order_challenge.http.key_authorization
}

# Output challenge details for manual deployment
output "challenge_token" {
  value = data.vault_pki_secret_backend_external_ca_order_challenge.http.token
}

output "challenge_url" {
  value = "http://www.example.com/.well-known/acme-challenge/${data.vault_pki_secret_backend_external_ca_order_challenge.http.token}"
}
```

## Example Usage with DNS-01 Challenge

```hcl
# Retrieve DNS-01 challenge details
data "vault_pki_secret_backend_external_ca_order_challenge" "dns" {
  mount          = vault_mount.pki.path
  role_name      = vault_pki_secret_backend_external_ca_role.example.name
  order_id       = vault_pki_secret_backend_external_ca_order.example.order_id
  challenge_type = "dns-01"
  identifier     = "www.example.com"
}

# Create DNS TXT record using AWS Route53
resource "aws_route53_record" "acme_challenge" {
  zone_id = aws_route53_zone.example.zone_id
  name    = "_acme-challenge.www.example.com"
  type    = "TXT"
  ttl     = 60
  records = [data.vault_pki_secret_backend_external_ca_order_challenge.dns.key_authorization]
}

# Output DNS record details
output "dns_record_name" {
  value = "_acme-challenge.www.example.com"
}

output "dns_record_value" {
  value     = data.vault_pki_secret_backend_external_ca_order_challenge.dns.key_authorization
  sensitive = true
}
```

## Example Usage with TLS-ALPN-01 Challenge

```hcl
# Retrieve TLS-ALPN-01 challenge details
data "vault_pki_secret_backend_external_ca_order_challenge" "tls_alpn" {
  mount          = vault_mount.pki.path
  role_name      = vault_pki_secret_backend_external_ca_role.example.name
  order_id       = vault_pki_secret_backend_external_ca_order.example.order_id
  challenge_type = "tls-alpn-01"
  identifier     = "www.example.com"
}

# Output challenge details for TLS configuration
output "tls_alpn_key_auth" {
  value     = data.vault_pki_secret_backend_external_ca_order_challenge.tls_alpn.key_authorization
  sensitive = true
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

* `challenge_type` - (Required) The type of ACME challenge to retrieve. Valid values are:
  - `http-01` - HTTP challenge (requires placing a file at a specific URL)
  - `dns-01` - DNS challenge (requires creating a TXT record)
  - `tls-alpn-01` - TLS-ALPN challenge (requires configuring TLS with specific ALPN extension)

* `identifier` - (Required) The identifier (domain name) for which to retrieve the challenge.

## Attributes Reference

The following attributes are exported:

* `id` - Unique identifier for this data source read.

* `token` - The challenge token provided by the ACME server. For HTTP-01 challenges, this is used in the URL path.

* `key_authorization` - The key authorization string for the challenge. This is the value that must be:
  - Served at the challenge URL for HTTP-01
  - Set as the TXT record value for DNS-01
  - Used in the TLS certificate for TLS-ALPN-01

* `status` - The current status of the challenge (e.g., `pending`, `valid`, `invalid`).

* `expires` - Expiry time for the challenge in RFC3339 format.

## Challenge Type Details

### HTTP-01 Challenge

For HTTP-01 challenges, you must serve the `key_authorization` value at:
```
http://<identifier>/.well-known/acme-challenge/<token>
```

The response must:
- Return HTTP 200 status
- Have Content-Type: `text/plain` or no Content-Type header
- Contain only the `key_authorization` value

### DNS-01 Challenge

For DNS-01 challenges, you must create a TXT record at:
```
_acme-challenge.<identifier>
```

The TXT record value must be the `key_authorization` value. DNS propagation may take time, so ensure the record is resolvable before marking the challenge as fulfilled.

### TLS-ALPN-01 Challenge

For TLS-ALPN-01 challenges, you must configure your TLS server to:
- Present a self-signed certificate for the identifier
- Include the `acme-tls/1` ALPN protocol
- Include a specific extension with the `key_authorization` value

This challenge type is more complex and typically requires custom TLS server configuration.

~> **Note** This data source polls the order status with a maximum of 5 attempts at 2-second intervals. If the order does not reach the appropriate state within this time, the data source read will fail.