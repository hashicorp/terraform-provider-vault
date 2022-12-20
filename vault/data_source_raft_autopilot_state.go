package vault

import (
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
	consts.FieldRedundancyZones,
	consts.FieldServers,
	consts.FieldUpgradeInfo,
	consts.FieldVoters,
}

func raftAutopilotStateDataSource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldFailureTolerance: {
			Type:        schema.TypeInt,
			Computed:    true,
			Description: "How many nodes could fail before the cluster becomes unhealthy",
		},
		consts.FieldHealthy: {
			Type:        schema.TypeString,
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
		consts.FieldRedundancyZones: {
			Type:     schema.TypeMap,
			Computed: true,
			Elem: &schema.Schema{
				Elem: map[string]*schema.Schema{
					"servers": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"voters": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"failure_tolerance": {
						Type: schema.TypeInt,
					},
				},
			},
			Description: "Additional output related to redundancy zones.",
		},
		consts.FieldServers: {
			Type:     schema.TypeMap,
			Computed: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"id": {
						Type: schema.TypeString,
					},
					"name": {
						Type: schema.TypeString,
					},
					"address": {
						Type: schema.TypeString,
					},
					"node_status": {
						Type: schema.TypeString,
					},
					"last_contact": {
						Type: schema.TypeString,
					},
					"last_term": {
						Type: schema.TypeInt,
					},
					"last_index": {
						Type: schema.TypeInt,
					},
					"healthy": {
						Type: schema.TypeBool,
					},
					"stable_since": {
						Type: schema.TypeString,
					},
					"status": {
						Type: schema.TypeString,
					},
					"version": {
						Type: schema.TypeString,
					},
					"upgrade_version": {
						Type: schema.TypeString,
					},
					"redundancy_zone": {
						Type: schema.TypeString,
					},
					"node_type": {
						Type: schema.TypeString,
					},
				},
			},
			Description: "A node in a Vault cluster.",
		},
		consts.FieldUpgradeInfo: {
			Type:     schema.TypeMap,
			Computed: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"status": {
						Type: schema.TypeString,
					},
					"target_version": {
						Type: schema.TypeString,
					},
					"target_version_voters": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"target_version_non_voters": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"target_version_read_replicas": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"other_version_voters": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"other_version_non_voters": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"other_version_read_replicas": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"redundancy_zones": {
						Type:     schema.TypeMap,
						Computed: true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"target_version_voters": {
									Type: schema.TypeList,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"target_version_non_voters": {
									Type: schema.TypeList,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"other_version_voters": {
									Type: schema.TypeList,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"other_version_non_voters": {
									Type: schema.TypeList,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
							},
						},
						Description: "Additional output related to automated upgrades.",
					},
				},
			},
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

	return nil
}
