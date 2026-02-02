---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-gcp-auth-backend-role"
description: |-
  Managing roles in an GCP auth backend in Vault
---

# vault\_gcp\_auth\_backend

Provides a resource to configure the [GCP auth backend within Vault](https://www.vaultproject.io/docs/auth/gcp.html).

## Example Usage
You can setup the GCP auth backend with Workload Identity Federation (WIF) for a secret-less configuration:
```hcl
resource "vault_gcp_auth_backend" "gcp" {
  identity_token_key      = "example-key"
  identity_token_ttl      = 1800
  identity_token_audience = "<TOKEN_AUDIENCE>"
  service_account_email   = "<SERVICE_ACCOUNT_EMAIL>"
  rotation_schedule       = "0 * * * SAT"
  rotation_window         = 3600
}
```

```hcl
resource "vault_gcp_auth_backend" "gcp" { 
  credentials       = file("vault-gcp-credentials.json")
  rotation_schedule = "0 * * * SAT"
  rotation_window   = 3600

  custom_endpoint = {
    api     = "www.googleapis.com"
    iam     = "iam.googleapis.com"
    crm     = "cloudresourcemanager.googleapis.com"
    compute = "compute.googleapis.com"
  }
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

* `credentials` - (Optional) A JSON string containing the contents of a GCP credentials file. If this value is empty, Vault will try to use Application Default Credentials from the machine on which the Vault server is running. Mutually exclusive with `credentials_wo`.

* `credentials_wo_version` - (Optional) A version counter for write-only credentials. Incrementing this value will cause the provider to send the credentials to Vault. Required with `credentials_wo`.
  For more information about write-only attributes, see
  [using write-only attributes](/docs/providers/vault/guides/using_write_only_attributes).

* `path` - (Optional) The path to mount the auth method — this defaults to 'gcp'.

* `disable_remount` - (Optional) If set, opts out of mount migration on path updates.
  See here for more info on [Mount Migration](https://www.vaultproject.io/docs/concepts/mount-migration)

* `description` - (Optional) A description of the auth method.

* `local` - (Optional) Specifies if the auth method is local only.

* `service_account_email` – (Optional) Service Account to impersonate for plugin workload identity federation.
  Required with `identity_token_audience`. Requires Vault 1.17+. *Available only for Vault Enterprise*.

* `identity_token_audience` - (Optional) The audience claim value for plugin identity
  tokens. Must match an allowed audience configured for the target [Workload Identity Pool](https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers#prepare).
  Mutually exclusive with `credentials`.  Requires Vault 1.17+. *Available only for Vault Enterprise*.

* `identity_token_ttl` - (Optional) The TTL of generated tokens. Defaults to
  1 hour. Uses [duration format strings](https://developer.hashicorp.com/vault/docs/concepts/duration-format).
  Requires Vault 1.17+. *Available only for Vault Enterprise*.

* `identity_token_key` - (Optional) The key to use for signing plugin identity
  tokens. Requires Vault 1.17+. *Available only for Vault Enterprise*.

* `iam_alias` - (Optional) Defines what alias needs to be used during login and refelects the same in token metadata and audit logs.

* `iam_metadata` - (Optional) Controls the metadata to include on the token returned by the login endpoint.

* `gce_alias` - (Optional) Defines what alias needs to be used during login and refelects the same in token metadata and audit logs.

* `gce_metadata` - (Optional) Controls which instance metadata fields from the GCE login are captured into Vault's token metadata or audit logs.

* `custom_endpoint` - (Optional) Specifies overrides to
  [service endpoints](https://cloud.google.com/apis/design/glossary#api_service_endpoint)
  used when making API requests. This allows specific requests made during authentication
  to target alternative service endpoints for use in [Private Google Access](https://cloud.google.com/vpc/docs/configure-private-google-access)
  environments. Requires Vault 1.11+.

  Overrides are set at the subdomain level using the following keys:
  - `api` - Replaces the service endpoint used in API requests to `https://www.googleapis.com`.
  - `iam` - Replaces the service endpoint used in API requests to `https://iam.googleapis.com`.
  - `crm` - Replaces the service endpoint used in API requests to `https://cloudresourcemanager.googleapis.com`.
  - `compute` - Replaces the service endpoint used in API requests to `https://compute.googleapis.com`.

  The endpoint value provided for a given key has the form of `scheme://host:port`.
  The `scheme://` and `:port` portions of the endpoint value are optional.

* `rotation_period` - (Optional) The amount of time in seconds Vault should wait before rotating the root credential.
  A zero value tells Vault not to rotate the root credential. The minimum rotation period is 10 seconds. Requires Vault Enterprise 1.19+.

* `rotation_schedule` - (Optional) The schedule, in [cron-style time format](https://en.wikipedia.org/wiki/Cron),
  defining the schedule on which Vault should rotate the root token. Requires Vault Enterprise 1.19+.

* `rotation_window` - (Optional) The maximum amount of time in seconds allowed to complete
  a rotation when a scheduled token rotation occurs. The default rotation window is
  unbound and the minimum allowable window is `3600`. Requires Vault Enterprise 1.19+.

* `disable_automated_rotation` - (Optional) Cancels all upcoming rotations of the root credential until unset. Requires Vault Enterprise 1.19+.

* `tune` - (Optional) Extra configuration block. Structure is documented below.

The `tune` block is used to tune the auth backend:

* `default_lease_ttl` - (Optional) Specifies the default time-to-live.
  If set, this overrides the global default.
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `max_lease_ttl` - (Optional) Specifies the maximum time-to-live.
  If set, this overrides the global default.
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `audit_non_hmac_response_keys` - (Optional) Specifies the list of keys that will
  not be HMAC'd by audit devices in the response data object.

* `audit_non_hmac_request_keys` - (Optional) Specifies the list of keys that will
  not be HMAC'd by audit devices in the request data object.

* `listing_visibility` - (Optional) Specifies whether to show this mount in
  the UI-specific listing endpoint. Valid values are "unauth" or "hidden".

* `passthrough_request_headers` - (Optional) List of headers to whitelist and
  pass from the request to the backend.

* `allowed_response_headers` - (Optional) List of headers to whitelist and allowing
  a plugin to include them in the response.

* `token_type` - (Optional) Specifies the type of tokens that should be returned by
  the mount. Valid values are "default-service", "default-batch", "service", "batch".


For more details on the usage of each argument consult the [Vault GCP API documentation](https://www.vaultproject.io/api-docs/auth/gcp#configure).

## Ephemeral Attributes Reference

The following write-only attributes are supported:

* `credentials_wo` - (Optional) A JSON string containing the contents of a GCP credentials file. Can be updated. Mutually exclusive with `credentials`.
  If this value is empty, Vault will try to use Application Default Credentials from the machine on which the Vault server is running.
  **Note**: This property is write-only and will not be read from the API.

## Attribute Reference

In addition to the fields above, the following attributes are also exposed:

* `client_id` - The Client ID of the credentials

* `private_key_id` - The ID of the private key from the credentials

* `project_id` - The GCP Project ID

* `client_email` - The clients email associated with the credentials

* `accessor` - The mount accessor related to the auth mount. It is useful for integration with [Identity Secrets Engine](https://www.vaultproject.io/docs/secrets/identity/index.html).

## Import

GCP authentication backends can be imported using the backend name, e.g.

```
$ terraform import vault_gcp_auth_backend.gcp gcp
```
