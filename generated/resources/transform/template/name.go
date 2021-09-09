package template

// DO NOT EDIT
// This code is generated.

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

const nameEndpoint = "/transform/template/{name}"

func NameResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"path": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: `The mount path for a back-end, for example, the path given in "$ vault auth enable -path=my-aws aws".`,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"alphabet": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The alphabet to use for this template. This is only used during FPE transformations.`,
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `The name of the template.`,
			ForceNew:    true,
		},
		"pattern": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The pattern used for matching. Currently, only regular expression pattern is supported.`,
		},
		"type": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The pattern type to use for match detection. Currently, only regex is supported.`,
		},
	}
	return &schema.Resource{
		Create: createNameResource,
		Update: updateNameResource,
		Read:   readNameResource,
		Exists: resourceNameExists,
		Delete: deleteNameResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}
func createNameResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Get("path").(string)
	vaultPath := util.ParsePath(path, nameEndpoint, d)
	log.Printf("[DEBUG] Creating %q", vaultPath)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists("alphabet"); ok {
		data["alphabet"] = v
	}
	data["name"] = d.Get("name")
	if v, ok := d.GetOkExists("pattern"); ok {
		data["pattern"] = v
	}
	if v, ok := d.GetOkExists("type"); ok {
		data["type"] = v
	}

	log.Printf("[DEBUG] Writing %q", vaultPath)
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", vaultPath, err)
	}
	d.SetId(vaultPath)
	log.Printf("[DEBUG] Wrote %q", vaultPath)
	return readNameResource(d, meta)
}

func readNameResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Reading %q", vaultPath)

	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Read %q", vaultPath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}
	pathParams, err := util.PathParameters(nameEndpoint, vaultPath)
	if err != nil {
		return err
	}
	for paramName, paramVal := range pathParams {
		if err := d.Set(paramName, paramVal); err != nil {
			return fmt.Errorf("error setting state %q, %q: %s", paramName, paramVal, err)
		}
	}
	if val, ok := resp.Data["alphabet"]; ok {
		if err := d.Set("alphabet", val); err != nil {
			return fmt.Errorf("error setting state key 'alphabet': %s", err)
		}
	}
	if val, ok := resp.Data["pattern"]; ok {
		if err := d.Set("pattern", val); err != nil {
			return fmt.Errorf("error setting state key 'pattern': %s", err)
		}
	}
	if val, ok := resp.Data["type"]; ok {
		if err := d.Set("type", val); err != nil {
			return fmt.Errorf("error setting state key 'type': %s", err)
		}
	}
	return nil
}

func updateNameResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Updating %q", vaultPath)

	data := map[string]interface{}{}
	if raw, ok := d.GetOk("alphabet"); ok {
		data["alphabet"] = raw
	}
	if raw, ok := d.GetOk("pattern"); ok {
		data["pattern"] = raw
	}
	if raw, ok := d.GetOk("type"); ok {
		data["type"] = raw
	}
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Updated %q", vaultPath)
	return readNameResource(d, meta)
}

func deleteNameResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Deleting %q", vaultPath)

	if _, err := client.Logical().Delete(vaultPath); err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting %q: %s", vaultPath, err)
	} else if err != nil {
		log.Printf("[DEBUG] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted template auth backend role %q", vaultPath)
	return nil
}

func resourceNameExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", vaultPath)

	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", vaultPath)
	return resp != nil, nil
}
