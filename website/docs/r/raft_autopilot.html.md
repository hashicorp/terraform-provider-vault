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

- `cleanup_dead_servers` – (Optional) Specifies automatic removal of dead server 
nodes periodically.

- `dead_server_last_contact_threshold` - (Optional) Limit the amount of time a 
server can go without leader contact before being considered failed.

- `last_contact_threshold` - (Optional) Limit the amount of time a server can go 
without leader contact before being considered unhealthy.

- `max_trailing_logs` - (Optional) Maximum number of log entries in the Raft log 
that a server can be behind its leader before being considered unhealthy.

- `min_quorum` - (Optional) Minimum number of servers allowed in a cluster before 
autopilot can prune dead servers.

- `server_stabilization_time` - (Optional) Minimum amount of time a server must be 
stable in the 'healthy' state before being added to the cluster.

## Attributes Reference

No additional attributes are exported by this resource.
