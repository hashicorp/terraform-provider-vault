---
layout: "vault"
page_title: "Vault: vault_transit_secret_backend_key_version data source"
sidebar_current: "docs-vault-datasource-transit-secret-backend-key-version"
description: |-
  Read information about a specific version of a Vault Transit key
---

# vault\_transit\_secret\_backend\_key\_version

Reads information about a specific version of a Transit key, such as its type and public key.
With [crypto agility](/docs/providers/vault/r/transit_secret_backend_key.html#crypto-agility),
each version of a key can have a different type.

~> **Note**: Requires Vault Enterprise 2.2.0 or later.

## Example Usage

```hcl
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "signing" {
  backend       = vault_mount.transit.path
  name          = "signing_key"
  type          = "ml-dsa"
  parameter_set = "65"
}

data "vault_transit_secret_backend_key_version" "first" {
  backend = vault_mount.transit.path
  name    = vault_transit_secret_backend_key.signing.name
  version = 1
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
  *Available only for Vault Enterprise*.

* `backend` - (Required) The path the transit secret backend is mounted at, with no leading or trailing `/`s.

* `name` - (Required) The name of the key to read.

* `version` - (Optional) The version of the key to read. If unset or `0`, the latest version is returned.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `version` - The version that was read. This is the actual version number, even if the latest was requested.

* `type` - The type of this key version.

* `public_key` - The public key of this key version, for asymmetric key types.

* `parameter_set` - The parameter set of this key version, for ML-DSA, SLH-DSA and hybrid keys.

* `hybrid_key_type_ec` - The elliptic curve algorithm of this key version, for hybrid keys.

* `hybrid_key_type_pqc` - The post-quantum algorithm of this key version, for hybrid keys.

* `supports_encryption` - Whether or not this key version supports encryption, based on key type.

* `supports_decryption` - Whether or not this key version supports decryption, based on key type.

* `supports_derivation` - Whether or not this key version supports derivation, based on key type.

* `supports_signing` - Whether or not this key version supports signing, based on key type.
