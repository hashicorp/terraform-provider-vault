package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	autopilotPath     = "sys/storage/raft/autopilot/configuration"
	autopilotDefaults = map[string]interface{}{
		"cleanup_dead_servers":               false,
		"dead_server_last_contact_threshold": "24h0m0s",
		"last_contact_threshold":             "10s",
		"max_trailing_logs":                  1000,
		"min_quorum":                         3,
		"server_stabilization_time":          "10s",
		"disable_upgrade_migration":          false,
	}
)

func raftAutopilotConfigResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"cleanup_dead_servers": {
			Type:        schema.TypeBool,
			Description: "Specifies whether to remove dead server nodes periodically or when a new server joins. This requires that min-quorum is also set.",
			Default:     autopilotDefaults["cleanup_dead_servers"],
			Optional:    true,
		},
		"dead_server_last_contact_threshold": {
			Type:        schema.TypeString,
			Description: "Limit the amount of time a server can go without leader contact before being considered failed. This only takes effect when cleanup_dead_servers is set.",
			Default:     autopilotDefaults["dead_server_last_contact_threshold"],
			Optional:    true,
		},
		"last_contact_threshold": {
			Type:        schema.TypeString,
			Description: "Limit the amount of time a server can go without leader contact before being considered unhealthy.",
			Default:     autopilotDefaults["last_contact_threshold"],
			Optional:    true,
		},
		"max_trailing_logs": {
			Type:        schema.TypeInt,
			Description: "Maximum number of log entries in the Raft log that a server can be behind its leader before being considered unhealthy.",
			Default:     autopilotDefaults["max_trailing_logs"],
			Optional:    true,
		},
		"min_quorum": {
			Type:        schema.TypeInt,
			Description: "Minimum number of servers allowed in a cluster before autopilot can prune dead servers. This should at least be 3. Applicable only for voting nodes.",
			Default:     autopilotDefaults["min_quorum"],
			Optional:    true,
		},
		"server_stabilization_time": {
			Type:        schema.TypeString,
			Description: "Minimum amount of time a server must be stable in the 'healthy' state before being added to the cluster.",
			Default:     autopilotDefaults["server_stabilization_time"],
			Optional:    true,
		},
		"disable_upgrade_migration": {
			Type:        schema.TypeBool,
			Description: "Disables automatically upgrading Vault using autopilot. (Enterprise-only)",
			Default:     autopilotDefaults["disable_upgrade_migration"],
			Optional:    true,
		},
	}
	return &schema.Resource{
		Create: createOrUpdateAutopilotConfigResource,
		Update: createOrUpdateAutopilotConfigResource,
		Read:   ReadWrapper(readAutopilotConfigResource),
		Delete: deleteAutopilotConfigResource,
		Schema: fields,
	}
}

func createOrUpdateAutopilotConfigResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	c := map[string]interface{}{
		"cleanup_dead_servers":               d.Get("cleanup_dead_servers").(bool),
		"last_contact_threshold":             d.Get("last_contact_threshold").(string),
		"dead_server_last_contact_threshold": d.Get("dead_server_last_contact_threshold").(string),
		"max_trailing_logs":                  d.Get("max_trailing_logs").(int),
		"min_quorum":                         d.Get("min_quorum").(int),
		"server_stabilization_time":          d.Get("server_stabilization_time").(string),
		"disable_upgrade_migration":          d.Get("disable_upgrade_migration").(bool),
	}

	log.Print("[DEBUG] Configuring autopilot")
	if _, err := client.Logical().Write(autopilotPath, c); err != nil {
		return fmt.Errorf("error writing %q: %s", autopilotPath, err)
	}
	log.Print("[DEBUG] Configured autopilot")
	d.SetId(autopilotPath)

	return readAutopilotConfigResource(d, meta)
}

func readAutopilotConfigResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	log.Printf("[DEBUG] Reading %q", autopilotPath)

	resp, err := client.Logical().Read(autopilotPath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", autopilotPath, err)
	}

	if val, ok := resp.Data["cleanup_dead_servers"]; ok {
		if err := d.Set("cleanup_dead_servers", val); err != nil {
			return fmt.Errorf("error setting state key 'cleanup_dead_servers': %s", err)
		}
	}

	if val, ok := resp.Data["last_contact_threshold"]; ok {
		if err := d.Set("last_contact_threshold", val); err != nil {
			return fmt.Errorf("error setting state key 'last_contact_threshold': %s", err)
		}
	}

	if val, ok := resp.Data["dead_server_last_contact_threshold"]; ok {
		if err := d.Set("dead_server_last_contact_threshold", val); err != nil {
			return fmt.Errorf("error setting state key 'dead_server_last_contact_threshold': %s", err)
		}
	}

	if val, ok := resp.Data["max_trailing_logs"]; ok {
		if err := d.Set("max_trailing_logs", val); err != nil {
			return fmt.Errorf("error setting state key 'max_trailing_logs': %s", err)
		}
	}

	if val, ok := resp.Data["min_quorum"]; ok {
		if err := d.Set("min_quorum", val); err != nil {
			return fmt.Errorf("error setting state key 'min_quorum': %s", err)
		}
	}

	if val, ok := resp.Data["server_stabilization_time"]; ok {
		if err := d.Set("server_stabilization_time", val); err != nil {
			return fmt.Errorf("error setting state key 'server_stabilization_time': %s", err)
		}
	}

	if val, ok := resp.Data["disable_upgrade_migration"]; ok {
		if err := d.Set("disable_upgrade_migration", val); err != nil {
			return fmt.Errorf("error setting state key 'disable_upgrade_migration': %s", err)
		}
	}

	return nil
}

func deleteAutopilotConfigResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	log.Print("[DEBUG] Resetting raft autopilot config")

	_, err := client.Logical().Write(autopilotPath, autopilotDefaults)
	if err != nil {
		return fmt.Errorf("error setting autopilot back to defaults: %s", err)
	}
	log.Print("[DEBUG] Reset raft autopilot config")
	return nil
}
