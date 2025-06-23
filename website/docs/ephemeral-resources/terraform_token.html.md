---
layout: "vault"
page_title: "Vault: ephemeral vault_terraform_token resource"
sidebar_current: "docs-vault-ephemeral-terraform-token"
description: |-
  Read an ephemeral dynamic secret from the Vault Terraform Secrets engine 

---

# vault\_terraform\_token

Reads an ephemeral dynamic secret from the Vault Terraform Secrets engine that is not stored in the remote TF state.
For more information, please refer to [the Vault documentation](https://developer.hashicorp.com/vault/docs/secrets/terraform)
for the TF Secrets engine.

~> **NOTE:** Due to the nature of ephemeral resources, which run on plan and apply, you should only use this resource with
token types that support multiple tokens; credential_type="user" or credential_type="team".

## Example Usage

```hcl
# revokes the tokens generated during plan but leaves 
# tokens created during `apply` for their full TTL

ephemeral "vault_terraform_token" "tf_token" {
  mount           = vault_terraform_cloud_secret_backend.example.backend
  role_name       = vault_terraform_cloud_secret_role.example.name
  revoke_on_close = terraform.applying ? true : false
}
```

## Full Usage

```hcl
resource "vault_terraform_cloud_secret_backend" "example" {
  token = var.token
}

resource "vault_terraform_cloud_secret_role" "example" {
  backend         = vault_terraform_cloud_secret_backend.example.backend
  name            = "my_role"
  team_id         = var.tfe_team_id
  credential_type = "team"
  ttl             = 120
  max_ttl         = 300
  description     = "team role"
}

ephemeral "vault_terraform_token" "tf_token" {
  mount           = vault_terraform_cloud_secret_backend.example.backend
  role_name       = vault_terraform_cloud_secret_role.example.name

  # mount_id only required on ephemeral resource if the ephemeral is called 
  # in the same run as its dependencies are created
  mount_id        = vault_terraform_cloud_secret_backend.example.mount_id
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) Name of the terraform role without trailing or leading slashes.
* `mount` - (Optional) Mount path for the TF engine in Vault without trailing or leading slashes. Defaults to `terraform`
* `mount_id` - (Optional) ID of the mount path. This argument is only helpful if you're calling the ephemeral resource
in the same terraform run as the dependencies are created. It should be omitted if your role is created in other runs.
* `revoke_on_close` - (Optional) If true, revokes the token once the provider closes. Ephemeral
tokens are generated on both plan and apply; see the example for setting revoke on 1 stage only. Defaults to true.


## Attributes Reference

The following attributes are exported in addition to the arguments listed above:

* `token` - the Terraform token generated for the specified role.
