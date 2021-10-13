package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func genericEndpointResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: genericEndpointResourceWrite,
		Update: genericEndpointResourceWrite,
		Delete: genericEndpointResourceDelete,
		Read:   genericEndpointResourceRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where to the endpoint that will be written",
			},

			// Data is passed as JSON so that an arbitrary structure is
			// possible, rather than forcing e.g. all values to be strings.
			"data_json": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "JSON-encoded data to write.",
				// We rebuild the attached JSON string to a simple single-line
				// string. This makes terraform not want to change when an
				// extra space is included in the JSON string. It is also
				// necessary when disable_read is false for comparing values.
				// NormalizeDataJSON and ValidateDataJSON are in
				// resource_generic_secret.
				StateFunc:    NormalizeDataJSON,
				ValidateFunc: ValidateDataJSON,
				Sensitive:    true,
			},

			"disable_read": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Don't attempt to read the path from Vault if true; drift won't be detected",
			},
			"disable_delete": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Don't attempt to delete the path from Vault if true",
			},
			"ignore_absent_fields": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "When reading, disregard fields not present in data_json",
			},
			"write_data_json": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON data returned by write operation",
			},
			"write_data": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings returned by write operation",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"write_fields": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Top-level fields returned by write to persist in state",
			},
		},
	}
}

func genericEndpointResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	var data map[string]interface{}
	err := json.Unmarshal([]byte(d.Get("data_json").(string)), &data)
	if err != nil {
		return fmt.Errorf("data_json %#v syntax error: %s", d.Get("data_json"), err)
	}

	path := d.Get("path").(string)
	log.Printf("[DEBUG] Writing generic Vault data to %s", path)
	response, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	writeDataMap := map[string]string{}
	if response != nil && response.Data != nil {

		// Since our "write_data" map can only contain string values, we
		// will take strings from Data and write them in as-is, and write
		// everything else in as a JSON serialization of whatever value we
		// get so that complex types can be passed around and processed
		// elsewhere if desired.
		writeData := make(map[string]interface{})
		iWriteFields := d.Get("write_fields").([]interface{})
		for _, iWriteField := range iWriteFields {
			writeField := iWriteField.(string)
			if _, ok := response.Data[writeField]; ok {
				v := response.Data[writeField]
				log.Printf("[DEBUG] %s found in response", writeField)
				writeData[writeField] = v
				if vs, ok := v.(string); ok {
					writeDataMap[writeField] = vs
				} else {
					// Ignoring error because we know this value came from JSON
					// in the first place and so must be valid.
					vBytes, _ := json.Marshal(v)
					writeDataMap[writeField] = string(vBytes)
				}
			} else {
				log.Printf("[DEBUG] %s not found in response", writeField)
			}
		}

		jsonData, err := json.Marshal(writeData)
		if err != nil {
			return fmt.Errorf("error marshaling JSON for %q: %s", path, err)
		}
		d.Set("write_data_json", string(jsonData))
	} else {
		d.Set("write_data_json", "null")
	}
	d.Set("write_data", writeDataMap)

	return genericEndpointResourceRead(d, meta)
}

func genericEndpointResourceDelete(d *schema.ResourceData, meta interface{}) error {
	shouldDelete := !d.Get("disable_delete").(bool)

	if shouldDelete {
		client := meta.(*api.Client)

		path := d.Id()

		log.Printf("[DEBUG] Deleting vault_generic_endpoint from %q", path)
		_, err := client.Logical().Delete(path)
		if err != nil {
			return fmt.Errorf("error deleting %q from Vault: %q", path, err)
		}
	}

	return nil
}

func genericEndpointResourceRead(d *schema.ResourceData, meta interface{}) error {
	shouldRead := !d.Get("disable_read").(bool)

	path := d.Id()
	ignore_absent_fields := d.Get("ignore_absent_fields").(bool)

	if shouldRead {
		client := meta.(*api.Client)

		log.Printf("[DEBUG] Reading %s from Vault", path)
		data, err := client.Logical().Read(path)

		if err != nil {
			return fmt.Errorf("error reading %s from Vault: %s", path, err)
		}
		if data == nil {
			log.Printf("[WARN] endpoint (%s) not found, removing from state", path)
			d.SetId("")
			return nil
		}

		log.Printf("[DEBUG] data from %q: %#v", path, data)

		var relevantData map[string]interface{}
		if ignore_absent_fields {
			var suppliedData map[string]interface{}
			err = json.Unmarshal([]byte(d.Get("data_json").(string)), &suppliedData)
			if err != nil {
				return fmt.Errorf("data_json %#v syntax error: %s", d.Get("data_json"), err)
			}
			relevantData = suppliedData
			for k, v := range data.Data {
				if _, ok := suppliedData[k]; ok {
					relevantData[k] = v
				}
			}
		} else {
			relevantData = data.Data
		}

		jsonData, err := json.Marshal(relevantData)
		if err != nil {
			return fmt.Errorf("error marshaling JSON for %q: %s", path, err)
		}
		d.Set("data_json", string(jsonData))
		d.Set("path", path)
	} else {
		log.Printf("[WARN] endpoint does not refresh when disable_read is set to true")
	}
	d.Set("disable_read", !shouldRead)
	d.Set("ignore_absent_fields", ignore_absent_fields)
	return nil
}
