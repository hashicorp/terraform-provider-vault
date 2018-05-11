package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func genericSecretResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: genericSecretResourceWrite,
		Update: genericSecretResourceWrite,
		Delete: genericSecretResourceDelete,
		Read:   genericSecretResourceRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		MigrateState: resourceGenericSecretMigrateState,

		Schema: map[string]*schema.Schema{
			"path": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the generic secret will be written.",
			},

			// Data is passed as JSON so that an arbitrary structure is
			// possible, rather than forcing e.g. all values to be strings.
			"data_json": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "JSON-encoded secret data to write.",
				// We rebuild the attached JSON string to a simple singleline
				// string. This makes terraform not want to change when an extra
				// space is included in the JSON string. It is also necesarry
				// when disable_read is false for comparing values.
				StateFunc:    NormalizeDataJSON,
				ValidateFunc: ValidateDataJSON,
			},

			"data": &schema.Schema{
				Type:        schema.TypeMap,
				Required:    false,
				Description: "Data returned from the resource.  Should be a map containing the content from data_json.",
				Computed:    true,
			},

			"allow_read": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Attempt to read the token from Vault if true; if false, drift won't be detected.",
				Deprecated:  "Please use disable_read instead.",
			},

			"disable_read": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Don't attempt to read the token from Vault if true; drift won't be detected.",
			},

			"capture_response": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If set to true, will disable read and capture the response to the write in the data object.",
			},
		},
	}
}

func ValidateDataJSON(configI interface{}, k string) ([]string, []error) {
	dataJSON := configI.(string)
	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(dataJSON), &dataMap)
	if err != nil {
		return nil, []error{err}
	}
	return nil, nil
}

func NormalizeDataJSON(configI interface{}) string {
	dataJSON := configI.(string)

	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(dataJSON), &dataMap)
	if err != nil {
		// The validate function should've taken care of this.
		log.Printf("[ERROR] Invalid JSON data in vault_generic_secret: %s", err)
		return ""
	}

	ret, err := json.Marshal(dataMap)
	if err != nil {
		// Should never happen.
		log.Printf("[ERROR] Problem normalizing JSON for vault_generic_secret: %s", err)
		return dataJSON
	}

	return string(ret)
}

func genericSecretResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	var data map[string]interface{}
	err := json.Unmarshal([]byte(d.Get("data_json").(string)), &data)
	if err != nil {
		return fmt.Errorf("data_json %#v syntax error: %s", d.Get("data_json"), err)
	}

	log.Printf("[DEBUG] Writing generic Vault secret to %s", path)
	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	captureResponse := d.Get("capture_response").(bool)
	if captureResponse {
		log.Printf("[DEBUG] Capture response is set.")
		if secret == nil {
			log.Printf("[WARN] write to (%s) returned empty response", path)
			return nil
		}
		jsonDataBytes, err := json.Marshal(secret.Data)
		if err != nil {
			return fmt.Errorf("Error marshaling JSON for %q: %s", path, err)
		}
		d.Set("data_json", string(jsonDataBytes))

		// Since our "data" map can only contain string values, we
		// will take strings from Data and write them in as-is,
		// and write everything else in as a JSON serialization of
		// whatever value we get so that complex types can be
		// passed around and processed elsewhere if desired.
		dataMap := map[string]string{}
		for k, v := range secret.Data {
			if vs, ok := v.(string); ok {
				dataMap[k] = vs
				continue
			}
			// Again ignoring error because we know this value
			// came from JSON in the first place and so must be valid.
			vBytes, _ := json.Marshal(v)
			dataMap[k] = string(vBytes)
		}
		d.Set("data", dataMap)

		d.Set("path", path)
		return nil
	}

	return genericSecretResourceRead(d, meta)
}

func genericSecretResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting vault_generic_secret from %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}

func genericSecretResourceRead(d *schema.ResourceData, meta interface{}) error {
	shouldRead := !d.Get("disable_read").(bool)
	if !shouldRead {
		// if disable_read is set to false or unset (we can't know which)
		// and allow_read is set to true, go with allow_read.
		shouldRead = d.Get("allow_read").(bool)
	}

	path := d.Id()

	if shouldRead {
		client := meta.(*api.Client)

		log.Printf("[DEBUG] Reading %s from Vault", path)
		secret, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading from Vault: %s", err)
		}
		if secret == nil {
			log.Printf("[WARN] secret (%s) not found, removing from state", path)
			d.SetId("")
			return nil
		}

		log.Printf("[DEBUG] secret: %#v", secret)

		jsonDataBytes, err := json.Marshal(secret.Data)
		if err != nil {
			return fmt.Errorf("Error marshaling JSON for %q: %s", path, err)
		}
		d.Set("data_json", string(jsonDataBytes))
		d.Set("path", path)
	} else {
		log.Printf("[WARN] vault_generic_secret does not refresh when disable_read is set to true")
	}
	d.Set("disable_read", !shouldRead)
	return nil
}
