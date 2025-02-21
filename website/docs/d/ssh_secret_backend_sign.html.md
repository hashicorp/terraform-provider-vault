---
layout: "vault"
page_title: "Vault: vault_ssh_secret_backend_sign data source"
sidebar_current: "docs-vault-datasource-ssh-secret-backend-sign"
description: |-
  Sign an SSH public key
---

# vault\_ssh\_secret\_backend\_sign

This is a data source which can be used to sign an SSH public key

## Example Usage

```hcl
data "vault_ssh_secret_backend_sign" "test" {
    path             = "ssh"
    public_key       = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDR6q4PTcuIkpdGEqaCaxnR8/REqlbSiEIKaRZkVSjiTXOaiSfUsy9cY2+7+oO9fLMUrhylImerjzEoagX1IjYvc9IeUBaRnfacN7QwUDfstgp2jknbg7rNX9j9nFxwltV/jYQPcRq8Ud0wn1nb4qixq+diM7+Up+xJOeaKxbpjEUJH5dcvaBB+Aa24tJpjOQxtFyQ6dUxlgJu0tcygZR92kKYCVjZDohlSED3i/Ak2KFwqCKx2IZWq9z1vMEgmRzv++4Qt1OsbpW8itiCyWn6lmV33eDCdjMrr9TEThQNnMinPrHdmVUnPZ/OomP+rLDRE9lQR16uaSvKhg5TWOFIXRPyEhX9arEATrE4KSWeQN2qgHOb6P24YqgEm1ZdHJq25q/nBBAa1x0tFMiWqZwOsGeJ9nTeOeyiqFKH5YRBo6DIy3ag3taFsfQSve6oqjnrudUd1hJ8/bNSz8amECfP0ULvAEAgpiurj3eCPc3OcXl4tAld9F6KwabEJV5eelcs= user@example.com"
    name             = "test"
    valid_principals = "my-user"
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) Full path where SSH backend is mounted.

* `name` - (Required) Specifies the name of the role to sign.

* `public_key` - (Required) Specifies the SSH public key that should be signed.

* `ttl` - (Optional) Specifies the Requested Time To Live. Cannot be greater than the role's max_ttl value. If not provided, the role's ttl value will be used. Note that the role values default to system values if not explicitly set.

* `valid_principals` (Optional) Specifies valid principals, either usernames or hostnames, that the certificate should be signed for. Required unless the role has specified allow_empty_principals or a value has been set for either the default_user or default_user_template role parameters.

* `cert_type` (Optional) Specifies the type of certificate to be created; either "user" or "host".

* `key_id` (Optional) Specifies the key id that the created certificate should have. If not specified, the display name of the token will be used.

* `critical_options` (Optional) Specifies a map of the critical options that the certificate should be signed for. Defaults to none.

* `extensions` (Optional) Specifies a map of the extensions that the certificate should be signed for. Defaults to none.

## Attributes Reference

* `serial_number` - The serial number of the certificate returned from Vault

* `signed_key` - The signed certificate returned from Vault
