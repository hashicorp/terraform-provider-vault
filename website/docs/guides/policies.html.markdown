---
layout: "vault"
page_title: "Vault Policies and the Terraform Vault Provider"
sidebar_current: "docs-vault-policies-and-tfvp"
description: |-
  Vault Policies and the Terraform Vault Provider

---

# Vault Policies and the Terraform Vault Provider

Vault uses policies to govern the behavior of clients and instrument Role-Based
Access Control (RBAC) by specifying access privileges (authorization).

Vault's [root](https://developer.hashicorp.com/vault/docs/concepts/policies#root-policy)
policy is capable of performing every operation for all paths. Root tokens are
tokens that have the `root` policy attached to them. Root tokens are useful in
development but should be carefully guarded in production.

In environments where permissions are least privilege, the Terraform Vault
Provider should not be given a token that has the root policy assigned to it.
Instead, the Vault provider should be given a token that limits its actions to only
the operations that it needs to provision Vault's resources.

For example, the following policy would limit the Vault provider to managing
the lifecycle of the Google Cloud secrets engine via the `vault_gcp_secret_backend`
resource:

```hcl
# Permit creating a new token that is a child of the one given
path "auth/token/create"
{
  capabilities = ["update"]
}

# Permit managing the lifecycle of the gcp secrets engine mount
path "sys/mounts/gcp"
{
  capabilities = ["read", "create", "update", "delete", "sudo"]
}

# Permit reading tune metadata of the gcp secrets engine
path "sys/mounts/gcp/tune"
{
  capabilities = ["read"]
}

# Permit managing the lifecycle of the gcp secrets engine configuration
path "gcp/config"
{
  capabilities = ["create", "update", "read"]
}
```

# Vault Policy Resources

For more details on Vault policies see:

- [Vault Policies Documentation](https://developer.hashicorp.com/vault/docs/concepts/policies)
- [Vault Policies Tutorial](https://developer.hashicorp.com/vault/tutorials/policies/policies)


