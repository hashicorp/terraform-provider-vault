---
layout: "vault"
page_title: "Vault: vault_raft_autopilot_state data"
sidebar_current: "docs-vault-raft-autopilot-state"
description: |-
  Retrieve the Raft cluster state.
---

# vault\_raft\_autopilot\_state

Displays the state of the raft cluster under integrated storage as seen by
autopilot. It shows whether autopilot thinks the cluster is healthy or not, and
how many nodes could fail before the cluster becomes unhealthy ("Failure
Tolerance"). For more information, please refer to the
[Vault documentation](https://developer.hashicorp.com/vault/api-docs/system/storage/raftautopilot#get-cluster-state).

## Example Usage

```hcl
data "vault_raft_autopilot_state" "main" {}

output "failure-tolerance" {
  value = data.vault_raft_autopilot_state.main.failure_tolerance
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace of the target resource.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault#namespace).
  *Available only for Vault Enterprise*.

## Attributes Reference

In addition to the arguments above, the following attributes are exported:

* `failure_tolerance` - How many nodes could fail before the cluster becomes unhealthy.

* `healthy` - Cluster health status.

* `leader` - The current leader of Vault.

* `optimistic_failure_tolerance` - The cluster-level optimistic failure tolerance.

* `redundancy_zones_json` - Additional output related to redundancy zones.

* `redundancy_zones` - Additional output related to redundancy zones stored as a serialized map of strings.

* `servers_json` - Additionaly output related to servers in the cluster.

* `servers` - Additionaly output related to servers in the cluster stored as a serialized map of strings.

* `upgrade_info_json` - Additional output related to upgrade information.

* `upgrade_info` - Additional output related to upgrade information stored as a serialized map of strings.

* `voters` - The voters in the Vault cluster.
