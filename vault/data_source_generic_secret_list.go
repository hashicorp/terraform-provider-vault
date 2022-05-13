package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/vault/api"
)

func genericSecretListDataSource() *schema.Resource {
	return &schema.Resource{
		Read: genericSecretListDataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where secret will be read.",
				ValidateFunc: validateNoTrailingSlash,
			},

			"data_json": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded secret data read from Vault.",
				Sensitive:   true,
			},

			"keys": {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of all secret keys.",
				Sensitive:   true,
			},

			"lease_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},

			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},

			"lease_renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func genericSecretListDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return err
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "metadata")
	}

	log.Printf("[DEBUG] Listing secrets at %s from Vault", path)

	resp, err := client.Logical().List(path)
	if err != nil {
		return fmt.Errorf("error listing from Vault at path %s, err=%w", path, err)
	}
	if resp == nil {
		return fmt.Errorf("no secrets found at %q", path)
	}

	d.SetId(path)

	// Ignoring error because this value came from JSON in the
	// first place so no reason why it should fail to re-encode.
	jsonDataBytes, _ := json.Marshal(resp.Data)
	if err := d.Set("data_json", string(jsonDataBytes)); err != nil {
		return err
	}

	// Set keys to state if there are keys in response
	if keyList, ok := resp.Data["keys"]; ok && keyList != nil {
		if keys, ok := keyList.([]string); ok {
			if err := d.Set("keys", keys); err != nil {
				return err
			}
		}
	}

	if err := d.Set("lease_id", resp.LeaseID); err != nil {
		return err
	}

	if err := d.Set("lease_duration", resp.LeaseDuration); err != nil {
		return err
	}

	if err := d.Set("lease_renewable", resp.Renewable); err != nil {
		return err
	}

	return nil
}
