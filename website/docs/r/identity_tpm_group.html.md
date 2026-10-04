---
layout: "vault"
page_title: "Vault: vault_identity_tpm_group resource"
sidebar_current: "docs-vault-resource-identity-tpm-group"
description: |-
  Creates an Identity TPM Group for Vault.
---

# vault\_identity\_tpm\_group

Creates an Identity TPM Group for Vault. TPM groups allow you to organize multiple TPM records
(machines with TPM 2.0 hardware) into logical groups for easier policy management and authorization.

~> **Important** This resource requires Vault Enterprise 2.2.0 or later.

## Example Usage

```hcl
resource "vault_identity_tpm" "server1" {
  name              = "production-server-01"
  tpm_ek_public_key = file("server1-ek.pem")
}

resource "vault_identity_tpm" "server2" {
  name              = "production-server-02"
  tpm_ek_public_key = file("server2-ek.pem")
}

resource "vault_identity_tpm_group" "production_servers" {
  name = "production-servers"
  
  member_tpm_ids = [
    vault_identity_tpm.server1.tpm_id,
    vault_identity_tpm.server2.tpm_id,
  ]
  
  metadata = {
    environment = "production"
    team        = "platform"
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).

* `name` - (Optional) Name of the TPM group. Vault generates a name if one is not specified.

* `member_tpm_ids` - (Optional) Set of TPM IDs that are members of this TPM group.
  These are the unique IDs assigned by Vault to TPM records (SHA256 of the EK public key).

* `metadata` - (Optional) A map of additional metadata to associate with the TPM group.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `tpm_group_id` - The unique ID Vault assigns to this TPM group.

## Import

Identity TPM groups can be imported using the `tpm_group_id`, e.g.

```
$ terraform import vault_identity_tpm_group.production_servers <tpm_group_id>
```
