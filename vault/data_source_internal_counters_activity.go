package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var countersStatePath = "sys/internal/counters/activity"

var internalCountersActivityStateFields = []string{
	consts.FieldByNamespace,
	consts.FieldEndTime,
	consts.FieldMonths,
	consts.FieldData,
	consts.FieldStartTime,
}

// serializeCounters is a map of fields that have complex structures that we will
// serialize for convenience instead of defining the schema explicitly
var serializeCounters = map[string]string{
	consts.FieldByNamespace: consts.FieldByNamespaceJSON,
	consts.FieldServers:     consts.FieldServersJSON,
	consts.FieldUpgradeInfo: consts.FieldUpgradeInfoJSON,
}

func internalCountersActivityStateDataSource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldDataJSON: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "How many nodes could fail before the cluster becomes unhealthy",
		},
		consts.FieldData: {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "How many nodes could fail before the cluster becomes unhealthy",
		},
		consts.FieldByNamespace: {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "How many nodes could fail before the cluster becomes unhealthy",
		},
		consts.FieldNamespaceId: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "How many nodes could fail before the cluster becomes unhealthy",
		},
		consts.FieldNamespacePath: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Path of this Namespace.",
		},
		consts.FieldCountsJSON: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Distinct Entity, Entity, & non-Entity Tokens & Clients",
		},
		consts.FieldCounts: {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "Distinct Entity, Entity, & non-Entity Tokens & Clients",
		},
		consts.FieldMonthsJSON: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Subkeys for the months read from Vault activity",
		},
		consts.FieldMonths: {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "Subkeys for the months read from Vault activity",
		},
		consts.FieldMounts: {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "Paths & Counts of auth & secrets engines",
		},
		consts.FieldEndTime: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Additional output related to redundancy zones stored as a map of strings.",
		},
		consts.FieldStartTime: {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "An RFC3339 timestamp or Unix epoch time. Specifies the start of the period for which client counts will be reported. If no start time is specified, the default_report_months prior to the end_time will be used.",
		},
	}
	return &schema.Resource{
		Read:   ReadWrapper(internalCountersActivityStateDataSourceRead),
		Schema: fields,
	}
}

func internalCountersActivityStateDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := countersStatePath

	log.Printf("[DEBUG] Reading internal counters activity state %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading internal counters activity state %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read internal counters activity state %q", path)

	if resp == nil {
		d.SetId("")
		log.Printf("[WARN] unable to read internal counters activity state at %q", path)
		return nil
	}

	d.SetId(path)
	for _, k := range internalCountersActivityStateFields {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for internal counters activity state %q: %q", k, path, err)
			}
		}
	}

	for k, v := range serializeCounters {
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
