---
layout: "vault"
page_title: "Vault: vault_quota_lease_count resource"
sidebar_current: "docs-vault-quota-lease-count"
description: |-
  Manage Lease Count Quota
---

# vault\_quota\_lease\_count

Manage lease count quotas which enforce the number of leases that can be created.
A lease count quota can be created at the root level or defined on a namespace or mount by
specifying a path when creating the quota.

See [Vault's Documentation](https://www.vaultproject.io/docs/enterprise/lease-count-quotas) for more
information.   

**Note** this feature is available only with Vault Enterprise.

## Example Usage

```hcl
resource "vault_quota_lease_count" "global" {
  name = "global"
  path = ""
  max_leases = 100
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the rate limit quota

* `path` - (Optional) Path of the mount or namespace to apply the quota. A blank path configures a
  global rate limit quota. For example `namespace1/` adds a quota to a full namespace,
  `namespace1/auth/userpass` adds a `quota` to `userpass` in `namespace1`.
  Updating this field on an existing quota can have "moving" effects. For example, updating
  `auth/userpass` to `namespace1/auth/userpass` moves this quota from being a global mount quota to
  a namespace specific mount quota. **Note, namespaces are supported in Enterprise only.**

* `max_leases` - (Required) The maximum number of leases to be allowed by the quota
  rule. The `max_leases` must be positive.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Lease count quotas can be imported using their names

```
$ terraform import vault_quota_lease_count.global global
```
