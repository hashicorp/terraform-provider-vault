---
layout: "vault"
page_title: "Vault: ephemeral vault_spiffe_mintjwt resource"
sidebar_current: "docs-vault-ephemeral-spiffe-mintjwt"
description: |-
  Mint a JWT token from the Vault SPIFFE Secrets engine 

---

# vault\_spiffe\_mintjwt

Creates and returns a JWT token based on the role's template, using JWT Compact Serialization format.

For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/docs/secrets/spiffe) for the SPIFFE Secrets engine.

## Example Usage

```hcl
resource "vault_mount" "spiffe_secrets" {
  path = "spiffe"
  type = "spiffe"
}

resource "vault_spiffe_backend_config" "spiffe_config" {
	mount			= vault_mount.spiffe_secrets.path
	trust_domain	= "example.com"
}

resource "vault_spiffe_role" "spiffe_role" {
  	mount		    = vault_mount.spiffe_secrets.path
  	name		    = "example-role"
  	template	    = jsonencode(
        {
            sub = "spiffe://example.com/workload"
        }
    )
}

ephemeral "vault_spiffe_mintjwt" "token" {
	mount		    = vault_mount.spiffe_mount.path
    mount_id	    = vault_mount.spiffe_mount.id
	name		    = vault_spiffe_role.spiffe_role.name

	audience	    = "test"
}
```

## Argument Reference

The following arguments are supported:

* `mount` - (Required) The SPIFFE secret backend the resource belongs to.

* `name`  - (Required) The name of the SPIFFE role to use to mint the JWT token.

* `audience` - (Required) The value to use for the `aud` claim in the JWT token.

## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `token` - The minted JWT token.

