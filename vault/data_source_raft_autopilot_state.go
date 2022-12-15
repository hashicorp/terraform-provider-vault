package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var autopilotStatePath = "sys/storage/raft/autopilot/state"

var raftAutopilotStateFields = []string{
	"failure_tolerance",
	"type",
	"bound_service_accounts",
	"bound_projects",
	"bound_zones",
	"bound_regions",
	"bound_instance_groups",
	"token_policies",
}

func raftAutopilotStateDataSource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"failure_tolerance": {
			Type: schema.TypeInt,
			// TODO(JM): do we actually need descriptions for this data source?
			Description: "How many nodes could fail before the cluster becomes unhealthy",
		},
		"healthy": {
			Type:        schema.TypeString,
			Description: "Health status",
		},
		"leader": {
			Type:        schema.TypeString,
			Description: "Current leader of Vault",
		},
		"optimistic_failure_tolerance": {
			Type: schema.TypeInt,
		},
		"redundancy_zones": {
			Type: schema.TypeMap,
			Elem: &schema.Schema{
				// TODO(JM): type map[string]struct ???
				Type: schema.TypeString,
			},
		},
		"servers": {
			Type: schema.TypeMap,
			Elem: &schema.Schema{
				// TODO(JM): type map[string]struct ???
				Type: schema.TypeString,
			},
		},
		"upgrade_info": {
			// TODO(JM): type struct ???
			Type: schema.TypeMap,
		},
		"voters": {
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
	}
	return &schema.Resource{
		Read:   ReadWrapper(raftAutopilotStateDataSourceRead),
		Schema: fields,
	}
}

func raftAutopilotStateDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := autopilotStatePath

	log.Printf("[DEBUG] Reading raft autopilot state %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading raft autopilot state %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read raft autopilot state %q", path)

	if resp == nil {
		d.SetId("")
		// TODO(JMF): do we return error or nil here?
		// return fmt.Errorf("unable to read raft autopilot state at %q", path)
		return nil
	}

	d.SetId(path)
	for _, k := range raftAutopilotStateFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for raft autopilot state %q: %q", k, path, err)
			}
		}
	}

	return nil
}
