---
layout: "vault"
page_title: "PKI Multi-Issuer Upgrade Guide"
sidebar_current: "docs-vault-pki-multi-issuer-upgrade"
description: |-
  Guide on how to upgrade to using the PKI Multi-Issuer feature.
---

# PKI Multi-Issuer Feature Upgrade Guide

Multi-issuer functionality for the PKI secrets engine is now available in 
the Vault Provider. The purpose of this guide is to make sure users that are 
adopting into this feature from an older Provider version are aware of the 
best migration practices.

For more information on multi-issuer functionality and how it is used,
please refer to the [Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/pki#notice-about-new-multi-issuer-functionality).

## Migrating from older version to multi-issuer enabled version of the Provider

### No existing PKI setup in the TF state 
There should be no behavioral changes in usage for users who are not using the PKI secrets engine.
If no PKI resources are being used in the Terraform, the migration to the new version of the Provider
should cleanly resolve the TF state.

### PKI engine setup already exists in TF state
Users already using the PKI secrets engine with single issuers who are now adopting into the
new multi-issuer enabled version should be aware of the possible changes made to their TF state.

By design, if you are migrating your existing TF state and now using multi-issuers,
the following resources may be destroyed and recreated. Please be aware of any changes
to your certificates:

- `vault_pki_secret_backend_root_cert`: If any new key or issuer data is added to the TF
  config or received from Vault, the old Root Certificate will be destroyed and a
  new one will be created.
- `vault_pki_secret_backend_intermediate_cert_request`: If any new key data is added to the TF
  config or received from Vault, the old Intermediate CSR will be destroyed and a
  new one will be created.
- `vault_pki_secret_backend_intermediate_set_signed`: If any newly imported issuers are
  received from Vault, the old set-signed will be destroyed and a new one will be initiated.

## Importing multi-issuers from Vault into TF state

Users that have set up PKI with multi-issuer functionality in Vault and are aiming to
import the multi-issuer data into the TF state can also use the following supported 
data sources to aid in migrating the data over to Terraform. These data sources should
also help inform users of any missing issuers/keys in the TF state.

- `vault_pki_secret_backend_issuers`: Lists all issuers under a particular mount.
- `vault_pki_secret_backend_issuer`: Reads data for a single existing issuer from Vault.
- `vault_pki_secret_backend_keys`: Lists all keys under a particular mount.
- `vault_pki_secret_backend_key`: Reads data for a single existing key from Vault.

These resources can be used to import any missing issuers/keys as follows:
```
data "vault_pki_secret_backend_keys" "root_keys" {
  backend = vault_mount.root.path
}

data "vault_pki_secret_backend_key" "missing_key" {
  backend = vault_mount.root.path
  key_ref = data.vault_pki_secret_backend_keys.root_keys.keys[0]
}

data "vault_pki_secret_backend_issuers" "root_issuers" {
  backend = vault_mount.root.path
}

data "vault_pki_secret_backend_issuer" "missing_issuer" {
  backend    = vault_mount.root.path
  issuer_ref = data.vault_pki_secret_backend_issuers.root_issuers.keys[0]
}
```

## Note on supported Vault versions
It should be noted that the multi-issuer enabled features of the Provider are well-tested
against Vault versions 1.11 and above. 

Users that are operating with Vault versions lower than 1.11 should be aware that it is 
recommended that they first upgrade their Vault server version before opting into any of the
newly enabled multi-issuer features. Once Vault has been upgraded to at least version 1.11,
upgrading the Vault Provider to using any of the multi-issuer features should resolve in a
clean TF state.
