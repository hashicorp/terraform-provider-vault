---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_crl_config resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-crl-config"
description: |-
  Sets the CRL config on an PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_crl\_config

Allows setting the duration for which the generated CRL should be marked valid. If the CRL is disabled, it will return a signed but zero-length CRL for any request. If enabled, it will re-build the CRL.

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path                      = "%s"
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_crl_config" "crl_config" {
  backend = vault_mount.pki.path
  expiry  = "72h"
  disable = false
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
   *Available only for Vault Enterprise*.

* `backend` - (Required) The path the PKI secret backend is mounted at, with no leading or trailing `/`s.

* `expiry` - (Optional) Specifies the time until expiration.

* `disable` - (Optional) Disables or enables CRL building.

* `ocsp_disable` - (Optional) Disables the OCSP responder in Vault. **Vault 1.12+**

* `ocsp_expiry` - (Optional) The amount of time an OCSP response can be cached for, useful for OCSP stapling 
 refresh durations. **Vault 1.12+**

* `auto_rebuild` - (Optional) Enables periodic rebuilding of the CRL upon expiry. **Vault 1.12+**

* `auto_rebuild_grace_period` - (Optional) Grace period before CRL expiry to attempt rebuild of CRL. **Vault 1.12+**

* `enable_delta` - (Optional) Enables building of delta CRLs with up-to-date revocation information, 
 augmenting the last complete CRL.  **Vault 1.12+**

* `delta_rebuild_interval` - (Optional) Interval to check for new revocations on, to regenerate the delta CRL.

* `cross_cluster_revocation` - (Optional) Enable cross-cluster revocation request queues. **Vault 1.13+**

* `unified_crl` - (Optional) Enables unified CRL and OCSP building. **Vault 1.13+**

* `unified_crl_on_existing_paths` - (Optional) Enables serving the unified CRL and OCSP on the existing, previously
 cluster-local paths. **Vault 1.13+**

## Attributes Reference

No additional attributes are exported by this resource.
