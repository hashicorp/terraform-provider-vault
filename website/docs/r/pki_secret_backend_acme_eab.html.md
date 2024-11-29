---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_acme_eab resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-acme-eab"
description: |-
  Creates ACME EAB tokens within the PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_acme_eab

Allows creating ACME EAB (External Account Binding) tokens and deleting unused ones.

## Example Usage

```hcl
resource "vault_mount" "test" {
  path        = "pki"
  type        = "pki"
  description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_acme_eab" "test" {
  backend = vault_mount.test.path
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) The path to the PKI secret backend to
  create the EAB token within, with no leading or trailing `/`s.

* `issuer` - (Optional) Create an EAB token that is specific to an issuer's ACME directory.

* `role` - (Optional) Create an EAB token that is specific to a role's ACME directory.

**NOTE**: Within Vault ACME there are different ACME directories which an EAB token is associated with;

 1. Default directory (`pki/acme/`) - Do not specify a value for issuer nor role parameters.
 2. Issuer specific (`pki/issuer/:issuer_ref/acme/`) - Specify a value for the issuer parameter
 3. Role specific (`pki/roles/:role/acme/`) - Specify a value for the role parameter
 4. Issuer and Role specific (`pki/issuer/:issuer_ref/roles/:role/acme/`) - Specify a value for both the issuer and role parameters

## Attributes Reference

* `eab_id` - The identifier of a specific ACME EAB token
* `key_type` - The key type of the EAB key
* `acme_directory` - The ACME directory to which the key belongs
* `key` - The EAB token 
* `created_on` - An RFC3339 formatted date time when the EAB token was created

## Import

As EAB tokens are only available on initial creation there is no possibility to 
import or update this resource.
