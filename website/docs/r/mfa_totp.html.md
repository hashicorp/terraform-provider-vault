---
layout: "vault"
page_title: "Vault: vault_mfa_totp resource"
sidebar_current: "docs-vault-resource-mfa-totp"
description: |-
  Managing the MFA TOTP method configuration
---

# vault\_mfa\_totp

Provides a resource to manage [TOTP MFA](https://www.vaultproject.io/docs/enterprise/mfa/mfa-totp).

**Note** this feature is available only with Vault Enterprise.

## Example Usage

```hcl
resource "vault_mfa_totp" "my_totp" {
  name      = "my_totp"
  issuer    = "hashicorp"
  period    = 60
  algorithm = "SHA256"
  digits    = 8
  key_size  = 20
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

- `name` `(string: <required>)` – Name of the MFA method.

- `issuer` `(string: <required>)` - The name of the key's issuing organization.

- `period` `(int)` - The length of time used to generate a counter for the TOTP token calculation.

- `key_size` `(int)` - Specifies the size in bytes of the generated key.

- `qr_size` `(int)` - The pixel size of the generated square QR code.

- `algorithm` `(string)` - Specifies the hashing algorithm used to generate the TOTP code.
  Options include `SHA1`, `SHA256` and `SHA512`

- `digits` `(int)` - The number of digits in the generated TOTP token.
  This value can either be 6 or 8.

- `skew` `(int)` - The number of delay periods that are allowed when validating a TOTP token.
  This value can either be 0 or 1.

- `max_validation_attempts` `(int)` - The maximum number of consecutive failed validation attempts allowed. Must be a positive integer. Vault defaults this value to `5` if not provided or if set to `0`.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Mounts can be imported using the `path`, e.g.

```
$ terraform import vault_mfa_totp.my_totp my_totp
```
