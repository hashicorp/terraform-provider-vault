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
	"github.com/hashicorp/terraform-provider-vault/util"
)

const latestSecretVersion = -1

func genericSecretResource(name string) *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: genericSecretResourceWrite,
		Update: genericSecretResourceWrite,
		Delete: genericSecretResourceDelete,
		Read:   provider.ReadWrapper(genericSecretResourceRead),
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		MigrateState: resourceGenericSecretMigrateState,

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the generic secret will be written.",
			},

			// Data is passed as JSON so that an arbitrary structure is
			// possible, rather than forcing e.g. all values to be strings.
			consts.FieldDataJSON: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "JSON-encoded secret data to write.",
				// We rebuild the attached JSON string to a simple singleline
				// string. This makes terraform not want to change when an extra
				// space is included in the JSON string. It is also necesarry
				// when disable_read is false for comparing values.
				StateFunc:    NormalizeDataJSONFunc(name),
				ValidateFunc: ValidateDataJSONFunc(name),
				Sensitive:    true,
			},

			"disable_read": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Don't attempt to read the token from Vault if true; drift won't be detected.",
			},

			"data": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},

			"delete_all_versions": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Only applicable for kv-v2 stores. If set, permanently deletes all versions for the specified key.",
			},
		},
	}
}

func ValidateDataJSONFunc(name string) func(c interface{}, k string) ([]string, []error) {
	return func(c interface{}, k string) ([]string, []error) {
		return validateDataJSON(name, c.(string), k)
	}
}

func validateDataJSON(name string, data, k string) ([]string, []error) {
	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(data), &dataMap)
	if err != nil {
		log.Printf("[ERROR] Failed to validate JSON data %q, resource=%q, key=%q, err=%s",
			data, name, k, err)
		return nil, []error{err}
	}
	return nil, nil
}

// NormalizeDataJSONFunc returns a NormalizeFunc that normalizes the JSON data
// for storage in the TF state for a given resource denoted by `name`.
func NormalizeDataJSONFunc(name string) func(c interface{}) string {
	return func(c interface{}) string {
		data := c.(string)
		result, err := normalizeDataJSON(data)
		if err != nil {
			// The validate function should've prevented invalid JSON ever getting here.
			log.Printf("[WARN] Failed to normalize JSON data %q, resource=%q, err=%s", data, name, err)
		}
		return result
	}
}

func normalizeDataJSON(data string) (string, error) {
	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(data), &dataMap)
	if err != nil {
		return "", err
	}

	ret, err := json.Marshal(dataMap)
	if err != nil {
		// Should never happen.
		return data, err
	}
	return string(ret), nil
}

func genericSecretResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(d.Get(consts.FieldDataJSON).(string)), &data); err != nil {
		return fmt.Errorf("data_json %#v syntax error: %s", d.Get(consts.FieldDataJSON), err)
	}

	path := d.Get(consts.FieldPath).(string)
	originalPath := path // if the path belongs to a v2 endpoint, it will be modified
	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error determining if it's a v2 path: %s", err)
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		data = map[string]interface{}{
			"data":    data,
			"options": map[string]interface{}{},
		}

	}

	if _, err := util.RetryWrite(client, path, data, util.DefaultRequestOpts()); err != nil {
		return err
	}

	d.SetId(originalPath)

	return genericSecretResourceRead(d, meta)
}

func genericSecretResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Id()

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error determining if it's a v2 path: %s", err)
	}

	if v2 {
		base := "data"
		deleteAllVersions := d.Get("delete_all_versions").(bool)
		if deleteAllVersions {
			base = consts.FieldMetadata
		}
		path = addPrefixToVKVPath(path, mountPath, base)
	}

	log.Printf("[DEBUG] Deleting vault_generic_secret from %q", path)
	_, err = client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}

func genericSecretResourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	var data map[string]interface{}
	shouldRead := !d.Get("disable_read").(bool)

	path := d.Id()

	if shouldRead {
		log.Printf("[DEBUG] Reading %s from Vault", path)
		secret, err := versionedSecret(latestSecretVersion, path, client)
		if err != nil {
			return fmt.Errorf("error reading from Vault: %s", err)
		}
		if secret == nil {
			log.Printf("[WARN] secret (%s) not found, removing from state", path)
			d.SetId("")
			return nil
		}

		data = secret.Data
		jsonData, err := json.Marshal(secret.Data)
		if err != nil {
			return fmt.Errorf("error marshaling JSON for %q: %s", path, err)
		}

		if err := d.Set(consts.FieldDataJSON, string(jsonData)); err != nil {
			return err
		}
		if err := d.Set(consts.FieldPath, path); err != nil {
			return err
		}
	} else {
		// Populate data from data_json from state
		err := json.Unmarshal([]byte(d.Get(consts.FieldDataJSON).(string)), &data)
		if err != nil {
			return fmt.Errorf("data_json %#v syntax error: %s", d.Get(consts.FieldDataJSON), err)
		}
		log.Printf("[WARN] vault_generic_secret does not refresh when disable_read is set to true")
	}

	if err := d.Set("disable_read", !shouldRead); err != nil {
		return err
	}

	dataMap := serializeDataMapToString(data)
	if err := d.Set("data", dataMap); err != nil {
		return err
	}

	if err := d.Set("delete_all_versions", d.Get("delete_all_versions")); err != nil {
		return err
	}

	return nil
}

func serializeDataMapToString(data map[string]interface{}) map[string]string {
	// Since our "data" map can only contain string values, we
	// will take strings from Data and write them in as-is,
	// and write everything else in as a JSON serialization of
	// whatever value we get so that complex types can be
	// passed around and processed elsewhere if desired.
	// Note: This is a different map to jsonData, as this can only
	// contain strings
	dataMap := map[string]string{}
	for k, v := range data {
		if vs, ok := v.(string); ok {
			dataMap[k] = vs
		} else {
			// Again ignoring error because we know this value
			// came from JSON in the first place and so must be valid.
			vBytes, _ := json.Marshal(v)
			dataMap[k] = string(vBytes)
		}
	}
	return dataMap
}
