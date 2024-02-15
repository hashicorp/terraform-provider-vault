// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var autopilotStatePath = "sys/storage/raft/autopilot/state"

var raftAutopilotStateFields = []string{
	consts.FieldFailureTolerance,
	consts.FieldHealthy,
	consts.FieldLeader,
	consts.FieldOptimisticFailureTolerance,
	consts.FieldVoters,
}

// serializeFields is a map of fields that have complex structures that we will
// serialize for convenience instead of defining the schema explicitly
var serializeFields = map[string]string{
	consts.FieldRedundancyZones: consts.FieldRedundancyZonesJSON,
	consts.FieldServers:         consts.FieldServersJSON,
	consts.FieldUpgradeInfo:     consts.FieldUpgradeInfoJSON,
}

func raftAutopilotStateDataSource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldFailureTolerance: {
			Type:        schema.TypeInt,
			Computed:    true,
			Description: "How many nodes could fail before the cluster becomes unhealthy",
		},
		consts.FieldHealthy: {
			Type:        schema.TypeBool,
			Computed:    true,
			Description: "Health status",
		},
		consts.FieldLeader: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Current leader of Vault",
		},
		consts.FieldOptimisticFailureTolerance: {
			Type:        schema.TypeInt,
			Computed:    true,
			Description: "The cluster-level optimistic failure tolerance.",
		},
		consts.FieldRedundancyZonesJSON: {
			Type:     schema.TypeString,
			Computed: true,
			// we save the subkeys as a JSON string in order to
			// cleanly support nested values
			Description: "Subkeys for the redundancy zones read from Vault.",
		},
		consts.FieldRedundancyZones: {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "Additional output related to redundancy zones stored as a map of strings.",
		},
		consts.FieldServersJSON: {
			Type:     schema.TypeString,
			Computed: true,
			// we save the subkeys as a JSON string in order to
			// cleanly support nested values
			Description: "Subkeys for the servers read from Vault.",
		},
		consts.FieldServers: {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "Additional output related to servers stored as a map of strings.",
		},
		consts.FieldUpgradeInfoJSON: {
			Type:     schema.TypeString,
			Computed: true,
			// we save the subkeys as a JSON string in order to
			// cleanly support nested values
			Description: "Subkeys for the servers read from Vault.",
		},
		consts.FieldUpgradeInfo: {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "Additional output related to upgrade info stored as a map of strings.",
		},
		consts.FieldVoters: {
			Type:     schema.TypeList,
			Computed: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description: "The voters in the Vault cluster.",
		},
	}
	return &schema.Resource{
		Read:   provider.ReadWrapper(raftAutopilotStateDataSourceRead),
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
		log.Printf("[WARN] unable to read raft autopilot state at %q", path)
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

	for k, v := range serializeFields {
		if data, ok := resp.Data[k]; ok {
			jsonData, err := json.Marshal(data)
			if err != nil {
				return fmt.Errorf("error marshaling JSON for %q at %q: %s", v, path, err)
			}
			if err := d.Set(v, string(jsonData)); err != nil {
				return err
			}

			if err := d.Set(k, serializeDataMapToString(data.(map[string]interface{}))); err != nil {
				return err
			}
		}
	}

	return nil
}
