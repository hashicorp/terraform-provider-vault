---
layout: "vault"
page_title: "Vault: vault_identity_tpm resource"
sidebar_current: "docs-vault-resource-identity-tpm"
description: |-
  Creates an Identity TPM record for Vault.
---

# vault\_identity\_tpm

Creates an Identity TPM record for Vault. TPM records represent individual machines with
TPM 2.0 hardware and are identified by their TPM Endorsement Key (EK) public key.

~> **Important** This resource requires Vault 2.2.0 or later.

## Example Usage

```hcl
resource "vault_identity_tpm" "machine1" {
  name             = "production-server-01"
  tpm_ek_public_key = <<-EOT
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
  EOT
  
  disabled = false
  
  metadata = {
    environment = "production"
    datacenter  = "us-west-2"
    owner       = "platform-team"
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `name` - (Required) Name of the TPM record.

* `tpm_ek_public_key` - (Required) PEM-encoded TPM Endorsement Key (EK) public key.
  This uniquely identifies the TPM hardware. **Note:** This field cannot be changed after
  creation; changing it will force recreation of the resource.

* `disabled` - (Optional) Whether the TPM is disabled. Defaults to `false`.

* `metadata` - (Optional) A map of additional metadata to associate with the TPM record.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `tpm_id` - The unique ID Vault assigns to this TPM record (SHA256 hash of the EK public key).

## Import

Identity TPM records can be imported using the `name`, e.g.

```
$ terraform import vault_identity_tpm.machine1 production-server-01
```
