---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_config_est resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-config-est"
description: |-
  Sets the EST configuration on a PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_config\_est

Allows setting the EST configuration on a PKI Secret Backend

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path        = "pki-root"
  type        = "pki"
  description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_role" "est_role" {
  backend = vault_mount.pki.path
  name = "est-role"
  ttl = 3600
  key_type = "ec"
  key_bits = "256"
}

resource "vault_pki_secret_backend_role" "est_role_2" {
  backend = vault_mount.pki.path
  name = "est-role-2"
  ttl = 3600
  key_type = "ec"
  key_bits = "256"
}

resource "vault_pki_secret_backend_config_est" "example" {
  backend = vault_mount.pki.path
  enabled = true
  default_mount = true
  default_path_policy = format("role:%s", vault_pki_secret_backend_role.est_role.name)
  label_to_path_policy = {
     "test-label": "sign-verbatim",
     "test-label-2": format("role:%s", vault_pki_secret_backend_role.est_role_2.name)
  }
  authenticators { 
	cert = { 
      "accessor" = "test", 
      "cert_role" = "cert-auth-role" 
    } 
	userpass = { 
      "accessor" = "test2" 
    } 
  }
  enable_sentinel_parsing = true
  audit_fields = ["csr", "common_name", "alt_names", "ip_sans", "uri_sans", "other_sans",
    "signature_bits", "exclude_cn_from_sans", "ou", "organization", "country",
    "locality", "province", "street_address", "postal_code", "serial_number",
    "use_pss", "key_type", "key_bits", "add_basic_constraints"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) The path to the PKI secret backend to
  read the EST configuration from, with no leading or trailing `/`s.

* `authenticators` - (Optional) Lists the mount accessors EST should delegate authentication requests towards (see [below for nested schema](#nestedatt--authenticators)).

* `default_mount` - (Optional) If set, this mount will register the default `.well-known/est` URL path. Only a single mount can enable this across a Vault cluster.

* `default_path_policy` - (Optional) Required to be set if default_mount is enabled. Specifies the behavior for requests using the default EST label. Can be sign-verbatim or a role given by role:<role_name>.

* `enable_sentinel_parsing` - (Optional) If set, parse out fields from the provided CSR making them available for Sentinel policies.

* `enabled` - (Optional) Specifies whether EST is enabled.

* `label_to_path_policy` - (Optional) Configures a pairing of an EST label with the redirected behavior for requests hitting that role. The path policy can be sign-verbatim or a role given by role:<role_name>. Labels must be unique across Vault cluster, and will register .well-known/est/<label> URL paths.

* `audit_fields` - (Optional) Fields parsed from the CSR that appear in the audit and can be used by sentinel policies.

<a id="nestedatt--authenticators"></a>
### Nested Schema for `authenticators`

* `cert` - "The accessor (required) and cert_role (optional) properties for cert auth backends".

* `userpass` - "The accessor (required) property for user pass auth backends".

## Attributes Reference

* `last_updated` - A read-only timestamp representing the last time the configuration was updated.

## Import

The PKI config cluster can be imported using the resource's `id`.
In the case of the example above the `id` would be `pki-root/config/est`,
where the `pki-root` component is the resource's `backend`, e.g.

```
$ terraform import vault_pki_secret_backend_config_est.example pki-root/config/est
```
