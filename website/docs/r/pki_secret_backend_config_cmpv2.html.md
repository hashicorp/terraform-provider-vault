---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_config_cmpv2 resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-config-cmpv2"
description: |-
  Sets the CMPv2 configuration on a PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_config\_cmpv2

Allows setting the CMPv2 configuration on a PKI Secret Backend

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path        = "pki-root"
  type        = "pki"
  description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_role" "cmpv2_role" {
  backend = vault_mount.pki.path
  name = "cmpv2-role"
  ttl = 3600
  key_type = "ec"
  key_bits = "256"
}

resource "vault_pki_secret_backend_role" "cmpv2_role_2" {
  backend = vault_mount.pki.path
  name = "cmpv2-role-2"
  ttl = 3600
  key_type = "ec"
  key_bits = "256"
}

resource "vault_pki_secret_backend_config_cmpv2" "example" {
  backend = vault_mount.pki.path
  enabled = true
  default_path_policy = format("role:%s", vault_pki_secret_backend_role.cmpv2_role.name)
  authenticators { 
	cert = { 
      "accessor" = "test", 
      "cert_role" = "cert-auth-role" 
    }
  }
  enable_sentinel_parsing = true
  audit_fields = ["csr", "common_name", "alt_names", "ip_sans", "uri_sans", "other_sans",
    "signature_bits", "exclude_cn_from_sans", "ou", "organization", "country",
    "locality", "province", "street_address", "postal_code", "serial_number",
    "use_pss", "key_type", "key_bits", "add_basic_constraints"]
  disabled_validations = ["DisableMatchingKeyIdValidation"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) The path to the PKI secret backend to
  read the CMPv2 configuration from, with no leading or trailing `/`s.

* `authenticators` - (Optional) Lists the mount accessors CMPv2 should delegate authentication requests towards (see [below for nested schema](#nestedatt--authenticators)).

* `default_path_policy` - (Optional) Specifies the behavior for requests using the non-role-qualified CMPv2 requests. Can be sign-verbatim or a role given by role:<role_name>.

* `enable_sentinel_parsing` - (Optional) If set, parse out fields from the provided CSR making them available for Sentinel policies.

* `enabled` - (Optional) Specifies whether CMPv2 is enabled.
  
* `audit_fields` - (Optional) Fields parsed from the CSR that appear in the audit and can be used by sentinel policies.
  
* `disabled_validations` - (Optional) A comma-separated list of validations not to perform on CMPv2 messages.

<a id="nestedatt--authenticators"></a>
### Nested Schema for `authenticators`

* `cert` - "The accessor (required) and cert_role (optional) properties for cert auth backends".

## Attributes Reference

* `last_updated` - A read-only timestamp representing the last time the configuration was updated.

## Import

The PKI config cluster can be imported using the resource's `id`.
In the case of the example above the `id` would be `pki-root/config/cmpv2`,
where the `pki-root` component is the resource's `backend`, e.g.

```
$ terraform import vault_pki_secret_backend_config_cmpv2.example pki-root/config/cmpv2
```
