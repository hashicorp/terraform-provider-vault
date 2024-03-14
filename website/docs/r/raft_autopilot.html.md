---
layout: "vault"
page_title: "Vault: vault_raft_autopilot resource"
sidebar_current: "docs-vault-raft-autopilot"
description: |-
  Configures Raft's Autopilot capabilities.
---

# vault\_raft\_autopilot

Autopilot enables automated workflows for managing Raft clusters. The 
current feature set includes 3 main features: Server Stabilization, Dead 
Server Cleanup and State API. **These three features are introduced in 
Vault 1.7.**

## Example Usage

```hcl
resource "vault_raft_autopilot" "autopilot" {
  cleanup_dead_servers = true
  dead_server_last_contact_threshold = "24h0m0s"
  last_contact_threshold = "10s"
  max_trailing_logs = 1000
  min_quorum = 3
  server_stabilization_time = "10s"
}
```

## Argument Reference

The following arguments are supported:

* `namespace` - (Optional) The namespace to provision the resource in.
  The value should not contain leading or trailing forward slashes.
  The `namespace` is always relative to the provider's configured [namespace](/docs/providers/vault/index.html#namespace).
   *Available only for Vault Enterprise*.

- `cleanup_dead_servers` – (Optional) Specifies whether to remove dead server nodes
periodically or when a new server joins. This requires that `min-quorum` is also set.

- `dead_server_last_contact_threshold` - (Optional) Limit the amount of time a 
server can go without leader contact before being considered failed. This only takes
effect when `cleanup_dead_servers` is set.

- `last_contact_threshold` - (Optional) Limit the amount of time a server can go 
without leader contact before being considered unhealthy.

- `max_trailing_logs` - (Optional) Maximum number of log entries in the Raft log 
that a server can be behind its leader before being considered unhealthy.

- `min_quorum` - (Optional) Minimum number of servers allowed in a cluster before 
autopilot can prune dead servers. This should at least be 3. Applicable only for
voting nodes.

- `server_stabilization_time` - (Optional) Minimum amount of time a server must be 
stable in the 'healthy' state before being added to the cluster.

- `disable_upgrade_migration` – (Optional) Disables automatically upgrading Vault using autopilot. (Enterprise-only)

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Raft Autopilot config can be imported using the ID, e.g.

```
$ terraform import vault_raft_autopilot.autopilot sys/storage/raft/autopilot/configuration
```
