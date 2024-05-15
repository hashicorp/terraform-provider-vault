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

* `authenticators` - (Optional) Lists the mount accessors EST should delegate authentication requests towards (see [below for nested schema](#nestedatt--authenticators))

* `default_mount` - Is this mount providing the cluster's default EST mount

* `default_path_policy` - (Optional) The behavior of the default_mount when enabled

* `enable_sentinel_parsing` - (Optional) Are fields from the provided CSR parsed out for Sentinel policies

* `enabled` - (Required) Is the EST feature enabled

* `label_to_path_policy` - (Optional) A pairing of EST label to the configured EST behavior for it

<a id="nestedatt--authenticators"></a>
### Nested Schema for `authenticators`

* `cert` - "The accessor (required) and cert_role (optional) properties for cert auth backends"

* `userpass` - "The accessor (required) property for user pass auth backends"

## Attributes Reference

No additional attributes are exported by this resource.

## Import

The PKI config cluster can be imported using the resource's `id`.
In the case of the example above the `id` would be `pki-root/config/est`,
where the `pki-root` component is the resource's `backend`, e.g.

```
$ terraform import vault_pki_secret_backend_config_est.example pki-root/config/est
```
