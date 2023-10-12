---
layout: "vault"
page_title: "Vault: vault_identity_mfa_totp resource"
sidebar_current: "docs-vault-resource-identity-mfa-totp"
description: |-
  Resource for configuring the totp MFA method.
---

# vault_identity_mfa_totp

Resource for configuring the totp MFA method.

## Example Usage


```hcl
resource "vault_identity_mfa_totp" "example" {
  issuer = "issuer1"
}
```
## Argument Reference

The following arguments are supported:

* `issuer` - (Required) The name of the key's issuing organization.
* `algorithm` - (Optional) Specifies the hashing algorithm used to generate the TOTP code. Options include SHA1, SHA256, SHA512.
* `digits` - (Optional) The number of digits in the generated TOTP token. This value can either be 6 or 8
* `key_size` - (Optional) Specifies the size in bytes of the generated key.
* `max_validation_attempts` - (Optional) The maximum number of consecutive failed validation attempts allowed.
* `mount_accessor` - (Optional) Mount accessor.
* `namespace` - (Optional) Target namespace. (requires Enterprise)
* `period` - (Optional) The length of time in seconds used to generate a counter for the TOTP token calculation.
* `qr_size` - (Optional) The pixel size of the generated square QR code.
* `skew` - (Optional) The number of delay periods that are allowed when validating a TOTP token. This value can either be 0 or 1.
* `uuid` - (Optional) Resource UUID.

## Attributes Reference


In addition to the fields above, the following attributes are exported:

* `method_id` - Method ID.
* `namespace_id` - Method's namespace ID.
* `namespace_path` - Method's namespace path.
* `type` - MFA type.

## Import

Resource can be imported using its `uuid` field, e.g.

```
$ terraform import vault_identity_mfa_totp.example 0d89c36a-4ff5-4d70-8749-bb6a5598aeec
```
