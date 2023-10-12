### Public Evaluation: Enhanced Vault namespace support

This directory contains sample Terraform code which demonstrates an enhanced way 
of provisioning resources under Vault namespaces. It assumes the following:

- Terraform is installed
- The provider development requirements are satisfied *see the top level README.md for more info*
- Root access to a Vault Enterprise server

#### Setup Terraform to use a local build of the Vault provider

> **warning**: backup your `~/.terraformrc` before running this command:

```shell
cat > ~/.terraformrc <<HERE
provider_installation {
  dev_overrides {
    "hashicorp/vault" = "$HOME/.terraform.d/plugins"
  }
  
  # For all other providers, install them directly from their origin provider
  # registries as normal. If you omit this, Terraform will _only_ use
  # the dev_overrides block, and so no other providers will be available.
  direct {}
}
HERE
```

Then execute the `dev` make target from the project root.
```shell
make dev
```

Now Terraform is set up to use the `dev` provider build instead of the provider
from the HashiCorp registry.

####  The basic example

Provision a generic KV secret in multiple namespaces using a single `provider{}` block.

Ensure that the `VAULT_TOKEN` and `VAULT_ADDR` environment variables are properly set, 
or an alternative auth method is configured.

*from the repo root*:

Apply the example
```shell
pushd eval/namespace-enhancements/examples/basic/.
terraform init
terraform apply
terraform output -json
popd
```

Destroy the example
```shell
pushd eval/namespace-enhancements/examples/basic/.
terraform destroy
popd
```
