---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_config_auto_tidy resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-config-auto-tidy"
description: |-
  Sets the Auto Tidy configuration on a PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_config\_auto\_tidy

Allows setting the Auto Tidy configuration on a PKI Secret Backend

## Example Usage

```hcl
resource "vault_mount" "pki" {
  path                      = "pki"
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_config_auto_tidy" "test" {
  backend = vault_mount.pki.path
  enabled = true
  tidy_cert_store = true
  interval_duration = "1h"
}
```

## Argument Reference

The following arguments are supported (at least one tidy operation is required):

* `enabled` - (Optional) Specifies whether automatic tidy is enabled or not.

* `acme_account_safety_buffer` - (Optional) The amount of time that must pass after creation that an
  account with no orders is marked revoked, and the amount of time after being marked revoked or
  deactivated.

* `interval_duration` - (Optional) Interval at which to run an auto-tidy operation. This is the time
  between tidy invocations (after one finishes to the start of the next).

* `issuer_safety_buffer` - (Optional) The amount of extra time that must have passed beyond issuer's
  expiration before it is removed from the backend storage.

* `maintain_stored_certificate_counts` - (Optional) This configures whether stored certificate are
  counted upon initialization of the backend, and whether during normal operation, a running count
  of certificates stored is maintained.

* `max_startup_backoff_duration` - (Optional) The maximum amount of time auto-tidy will be delayed
  after startup.

* `min_startup_backoff_duration` - (Optional) The minimum amount of time auto-tidy will be delayed
  after startup.

* `pause_duration` - (Optional) The amount of time to wait between processing certificates.

* `publish_stored_certificate_count_metrics` - (Optional) This configures whether the stored
  certificate count is published to the metrics consumer.

* `revocation_queue_safety_buffer` - (Optional) The amount of time that must pass from the
  cross-cluster revocation request being initiated to when it will be slated for removal.

* `safety_buffer` - (Optional) The amount of extra time that must have passed beyond certificate
  expiration before it is removed from the backend storage and/or revocation list.

* `tidy_acme` - (Optional) Set to true to enable tidying ACME accounts, orders and authorizations.

* `tidy_cert_metadata` - (Optional) Set to true to enable tidying up certificate metadata.

* `tidy_cert_store` - (Optional) Set to true to enable tidying up the certificate store

* `tidy_cmpv2_nonce_store` - (Optional) Set to true to enable tidying up the CMPv2 nonce store.

* `tidy_cross_cluster_revoked_certs` - (Optional) Set to true to enable tidying up the cross-cluster
  revoked certificate store.

* `tidy_expired_issuers` - (Optional) Set to true to automatically remove expired issuers past the
  `issuer_safety_buffer`. No keys will be removed as part of this operation.

* `tidy_move_legacy_ca_bundle` - (Optional) Set to true to move the legacy `ca_bundle` from
  `/config/ca_bundle` to `/config/ca_bundle.bak`.

* `tidy_revocation_queue` - (Optional) Set to true to remove stale revocation queue entries that
  haven't been confirmed by any active cluster.

* `tidy_revoked_cert_issuer_associations` - (Optional) Set to true to validate issuer associations
  on revocation entries. This helps increase the performance of CRL building and OCSP responses.

* `tidy_revoked_certs` - (Optional) Set to true to remove all invalid and expired certificates from
  storage. A revoked storage entry is considered invalid if the entry is empty, or the value within
  the entry is empty. If a certificate is removed due to expiry, the entry will also be removed from
  the CRL, and the CRL will be rotated.
