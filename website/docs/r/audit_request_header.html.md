---
layout: "vault"
page_title: "Vault: vault_audit_request_header resource"
sidebar_current: "docs-vault-resource-audit-request-header"
description: |-
  Manages audited request headers in Vault
---

# vault\_audit\_request\_header

Manages additional request headers that appear in audited requests.

~> **Note**
Because of the way the [sys/config/auditing/request-headers API](https://www.vaultproject.io/api-docs/system/config-auditing)
is implemented in Vault, this resource will manage existing audited headers with
matching names without requiring import.

## Example Usage

```hcl
resource "vault_audit_request_header" "x_forwarded_for" {
  name = "X-Forwarded-For"
  hmac = false
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the request header to audit.

* `hmac` - (Optional) Whether this header's value should be HMAC'd in the audit logs.

## Attributes Reference

No additional attributes are exported by this resource.
