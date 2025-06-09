---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_config_scep resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-config-scep"
description: |-
  Sets the SCEP configuration on a PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_config\_scep

Allows setting the SCEP configuration on a PKI Secret Backend.

## Example Usage

```hcl
resource "vault_auth_backend" "scep" {
    path = "scep-auth"
    type = "scep"
}

resource "vault_scep_auth_backend_role" "scep_challenge" {
    backend		 = vault_auth_backend.scep.id
    name		 = "scep-auth"
    display_name = "Static challenge for SCEP clients"
    auth_type	 = "static-challenge"
    challenge	 = "ac7e4ada-c8ef-4393-9098-d69d08736833"
}

resource "vault_mount" "pki" {
	path        = "pki_scep"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_config_scep" "test" {
  backend					  = vault_mount.pki.path
  enabled					  = true
  default_path_policy		  = "sign-verbatim"
  restrict_ca_chain_to_issuer = true
  authenticators {
    scep = {
      accessor  = vault_auth_backend.scep.accessor
      scep_role = vault_scep_auth_backend_role.scep_challenge.name 
    }
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) The path to the PKI secret backend to
  read the SCEP configuration from, with no leading or trailing `/`s.

* `allowed_digest_algorithms` - (Optional) List of allowed digest algorithms for SCEP requests.

* `allowed_encryption_algorithms` - (Optional) List of allowed encryption algorithms for SCEP requests.

* `authenticators` - (Optional) Lists the mount accessors SCEP should delegate authentication requests towards (see [below for nested schema](#nestedatt--authenticators)).

* `default_path_policy` - (Optional) Specifies the policy to be used for non-role-qualified SCEP requests; valid values are 'sign-verbatim', or "role:<role_name>" to specify a role to use as this policy.

* `enabled` - (Optional) Specifies whether SCEP is enabled.

* `external_validation` - (Optional) Lists the 3rd party validation of SCEP requests (see [below for nested schema](#nestedatt--externalvalidation)).

* `restrict_ca_chain_to_issuer` - (Optional) If true, only return the issuer CA, otherwise the entire CA certificate chain will be returned if available from the PKI mount.


<a id="nestedatt--authenticators"></a>
### Nested Schema for `authenticators`

* `cert` - The accessor (required) and cert_role (optional) properties for cert auth backends.

* `scep` - The accessor (required) property for scep auth backends.

<a id="nestedatt--externalvalidation"></a>
### Nested Schema for `external_validation`

* `intune` - The tenant_id (required), client_id (required), client_secret (required) and environment (optional) properties for Microsoft Intune validation of SCEP requests.

## Attributes Reference

* `last_updated` - A read-only timestamp representing the last time the configuration was updated.

## Import

The PKI config cluster can be imported using the resource's `id`.
In the case of the example above the `id` would be `pki-root/config/scep`,
where the `pki-root` component is the resource's `backend`, e.g.

```
$ terraform import vault_pki_secret_backend_config_scep.example pki-root/config/scep
```
