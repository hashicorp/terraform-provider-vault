---
layout: "vault"
page_title: "Vault: vault_generic_secret_metadata data source"
sidebar_current: "docs-vault-datasource-generic-secret-metadata"
description: |-
  Reads KVv2 Secret metadata from a given path in Vault
---

# vault\_generic\_secret\_metadata

Reads KVv2 Secret metadata from a given path in Vault.

This data source is solely intended to be used with
[Vault's "generic" secret backend](https://www.vaultproject.io/docs/secrets/generic/index.html),
kv version 2. In kv v1 there are no metadata.

~> **Important** the `custom_metadata` metadata requires vault v1.9.0

## Example Usage

```hcl
data "vault_generic_secret_metadata" "some_secret" {
  path = "secret/some_secret"
}

output "all_metadata" {
  value = data.vault_generic_secret_metadata.some_secret
}

output "custom_metadata" {
  value = data.vault_generic_secret_metadata.some_secret.custom_metadata
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) The full logical path from which to request data.
To read data from the "generic" secret backend mounted in Vault by
default, this should be prefixed with `secret/`. Reading from other backends
with this data source is possible; consult each backend's documentation
to see which endpoints support the `GET` method.

## Required Vault Capabilities

Use of this resource requires the `read` capability on the given path. (metadata)

## Attributes Reference

The following attributes are exported:

* `cas_required` - Boolean. When `true`, writes will only be allowed if the key’s current 
  version matches the version specified in the cas parameter.

* `custom_metadata` - A map of strings. This map can only represent string data.

* `delete_version_after` - String duration, Lifetime for a given version of a secret. eg. `17h23m12s`.
 This string will be parsed with [ParseDuration](https://pkg.go.dev/time#ParseDuration)

* `max_version` - Integer, maximum number of available versions

* `lease_id` - The lease identifier assigned by Vault, if any.

* `lease_duration` - The duration of the secret lease, in seconds relative
to the time the data was requested. Once this time has passed any plan
generated with this data may fail to apply.

* `lease_start_time` - The date and time of Terraform execution.
It is derived from the local machine's clock, and is
recorded in RFC3339 format UTC.
This can be used to approximate the absolute time represented by
`lease_duration`, though users must allow for any clock drift and response
latency relative to the Vault server. _Provided only as a convenience_.

* `lease_renewable` - `true` if the lease can be renewed using Vault's
`sys/renew/{lease-id}` endpoint. Terraform does not currently support lease
renewal, and so it will request a new lease each time this data source is
refreshed.
  

