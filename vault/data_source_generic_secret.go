package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func genericSecretDataSource() *schema.Resource {
	return &schema.Resource{
		Read: genericSecretDataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Full path from which a secret will be read.",
			},

			"version": {
				Type:     schema.TypeInt,
				Required: false,
				Optional: true,
				Default:  latestSecretVersion,
			},

			"with_lease_start_time": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				Description: "If set to true, stores 'lease_start_time' " +
					"in the TF state.",
			},

			"data_json": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded secret data read from Vault.",
				Sensitive:   true,
			},

			"data": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
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

			"lease_start_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the lease was read, using the clock of the system where Terraform was running",
			},

			"lease_renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func genericSecretDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get("path").(string)

	secretVersion := d.Get("version").(int)
	log.Printf("[DEBUG] Reading %s %d from Vault", path, secretVersion)

	secret, err := versionedSecret(secretVersion, path, client)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		return fmt.Errorf("no secret found at %q", path)
	}

	d.SetId(path)

	// Ignoring error because this value came from JSON in the
	// first place so no reason why it should fail to re-encode.
	jsonDataBytes, _ := json.Marshal(secret.Data)
	if err := d.Set("data_json", string(jsonDataBytes)); err != nil {
		return err
	}

	// Since our "data" map can only contain string values, we
	// will take strings from Data and write them in as-is,
	// and write everything else in as a JSON serialization of
	// whatever value we get so that complex types can be
	// passed around and processed elsewhere if desired.
	dataMap := map[string]string{}
	for k, v := range secret.Data {
		if vs, ok := v.(string); ok {
			dataMap[k] = vs
		} else {
			// Again ignoring error because we know this value
			// came from JSON in the first place and so must be valid.
			vBytes, _ := json.Marshal(v)
			dataMap[k] = string(vBytes)
		}
	}
	if err := d.Set("data", dataMap); err != nil {
		return err
	}

	if err := d.Set("lease_id", secret.LeaseID); err != nil {
		return err
	}

	if err := d.Set("lease_duration", secret.LeaseDuration); err != nil {
		return err
	}

	if err := d.Set("lease_renewable", secret.Renewable); err != nil {
		return err
	}

	if v, ok := d.GetOkExists("with_lease_start_time"); ok {
		if v.(bool) {
			if err := d.Set("lease_start_time", time.Now().UTC().Format(time.RFC3339)); err != nil {
				return err
			}
		}
	}
	return nil
}
