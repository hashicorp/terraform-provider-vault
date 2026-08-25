---
layout: "vault"
page_title: "Vault: vault_tpm_auth_backend_role resource"
sidebar_current: "docs-vault-resource-vault-tpm-auth-backend-role"
description: |-
  Manages TPM auth backend roles in Vault.
---

# vault\_tpm\_auth\_backend\_role

Manages a role in a TPM (Trusted Platform Module) auth backend. Roles define the mapping
from TPM identities and TPM groups to Vault policies and token parameters.

~> **Important** This resource requires Vault 2.2.0 or later.

## Example Usage

```hcl
resource "vault_auth_backend" "tpm" {
  type = "tpm"
  path = "tpm"
}

resource "vault_tpm_auth_backend_role" "example" {
  mount        = vault_auth_backend.tpm.path
  name         = "example-role"
  display_name = "Example TPM Role"
  cert_ttl     = "720h"
  
  tpm_ids = [
    "abc123...",
    "def456..."
  ]
  
  tpmgroup_ids = [
    "group-1",
    "group-2"
  ]
  
  token_ttl         = 3600
  token_max_ttl     = 7200
  token_policies    = ["default", "tpm-policy"]
  token_bound_cidrs = ["10.0.0.0/8"]
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `mount` - (Required) TPM auth backend mount path.

* `name` - (Required) Name of the TPM role.

* `display_name` - (Optional) Display name for the role. Defaults to the role name.

* `cert_ttl` - (Optional) Certificate TTL for the TPM role. Accepts duration format strings
  (e.g., "720h", "30d"). If not specified, uses the backend's default.

* `tpm_ids` - (Optional) Set of TPM record IDs authorized to authenticate with this role.
  These are the unique IDs assigned by Vault to TPM records (SHA256 of the EK public key).

* `tpmgroup_ids` - (Optional) Set of TPM group IDs authorized to authenticate with this role.

### Common Token Arguments

These arguments are common across several Authentication Token resources since Vault 1.2.

* `token_ttl` - (Optional) The incremental lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_max_ttl` - (Optional) The maximum lifetime for generated tokens in number of seconds.
  Its current value will be referenced at renewal time.

* `token_period` - (Optional) If set, indicates that the
  token generated using this role should never expire. The token should be renewed within the
  duration specified by this value. At each renewal, the token's TTL will be set to the
  value of this field. Specified in seconds.

* `token_policies` - (Optional) List of policies to encode onto generated tokens. Depending
  on the auth method, this list may be supplemented by user/group/other values.

* `token_bound_cidrs` - (Optional) List of CIDR blocks; if set, specifies blocks of IP
  addresses which can authenticate successfully, and ties the resulting token to these blocks
  as well.

* `token_explicit_max_ttl` - (Optional) If set, will encode an
  [explicit max TTL](https://www.vaultproject.io/docs/concepts/tokens.html#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token in number of seconds. This is a hard cap even if `token_ttl` and
  `token_max_ttl` would otherwise allow a renewal.

* `token_no_default_policy` - (Optional) If set, the default policy will not be set on
  generated tokens; otherwise it will be added to the policies set in token_policies.

* `token_num_uses` - (Optional) The maximum number of times a generated token may be used
  (within its lifetime); 0 means unlimited.

* `token_type` - (Optional) The type of token that should be generated. Can be `service`,
  `batch`, or `default` to use the mount's tuned default (which unless changed will be
  `service` tokens). For token store roles, there are two additional possibilities:
  `default-service` and `default-batch` which specify the type to return unless the client
  requests a different type at generation time.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

TPM auth backend roles can be imported using the resource's `id`.
In the case of the example above the `id` would be `auth/tpm/role/example-role`,
where the `tpm` component is the resource's `mount`, e.g.

```
$ terraform import vault_tpm_auth_backend_role.example auth/tpm/role/example-role
```
