---
layout: "vault"
page_title: "Vault: SSH Signed Key data source"
sidebar_current: "docs-vault-datasource-ssh-signed_key"
description: |-
  Sign a key for SSH access to a system
---

# vault\_ssh\_signed\_key

Signs an SSH public key for access to a system

This resource is intended to be used with
[Vault's "ssh" secret engine](https://www.vaultproject.io/api/secret/ssh/index.html),
configured with a CA.

## Example Usage

```hcl
resource "tls_private_key" "key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

data "vault_ssh_signed_key" "key" {
  backend = "ssh"
  role = "test-ca"
  valid_principals = "*"
  ttl = "1800"
  public_key = "${tls_private_key.key.public_key_openssh}"
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) Mount point for the SSH backend in Vault.
* `role` - (Required) Role used to sign in
* `cert_type` - (Required) Specifies the type of certificate to be created; either 'user' or 'host'.
* `public_key` - (Required) SSH Key to sign.
* `ttl` - (Optional) Time to live for the signature, defaults to 30 minutes.
* `valid_principals` - (Optional) Specifies valid principals, either usernames or hostnames, that the certificate should be signed for..
* `key_id` - (Optional) Specifies the key id that the created certificate should have. If not specified, the display name of the token will be used.


## Required Vault Capabilities

Use of this resource requires the `write` capability on the relevant paths (backend/sign/role).

## Attributes Reference

The following attributes are exported:

* `serial_number` - Serial of the signed certificate.

* `signed_key` - Key to use for logging into a system.

* `lease_id` - The lease identifier assigned by Vault, if any.

* `lease_duration` - The duration of the secret lease, in seconds relative
to the time the data was requested. Once this time has passed any plan
generated with this data may fail to apply.

* `lease_start_time` - As a convenience, this records the current time
on the computer where Terraform is running when the data is requested.
This can be used to approximate the absolute time represented by
`lease_duration`, though users must allow for any clock drift and response
latency relative to to the Vault server.

* `lease_renewable` - `true` if the lease can be renewed using Vault's
`sys/renew/{lease-id}` endpoint. Terraform does not currently support lease
renewal, and so it will request a new lease each time this data source is
refreshed.
