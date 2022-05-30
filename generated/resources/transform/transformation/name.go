package transformation

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

const nameEndpoint = "/transform/transformation/{name}"

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
		"allowed_roles": {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Description: `The set of roles allowed to perform this transformation.`,
		},
		"masking_character": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The character used to replace data when in masking mode`,
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `The name of the transformation.`,
			ForceNew:    true,
		},
		"template": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The name of the template to use.`,
		},
		"templates": {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Computed:    true,
			Description: `Templates configured for transformation.`,
		},
		"tweak_source": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The source of where the tweak value comes from. Only valid when in FPE mode.`,
		},
		"type": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The type of transformation to perform.`,
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
	if v, ok := d.GetOkExists("allowed_roles"); ok {
		data["allowed_roles"] = v
	}
	if v, ok := d.GetOkExists("masking_character"); ok {
		data["masking_character"] = v
	}
	data["name"] = d.Get("name")
	if v, ok := d.GetOkExists("template"); ok {
		data["template"] = v
	}
	if v, ok := d.GetOkExists("tweak_source"); ok {
		data["tweak_source"] = v
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
	if val, ok := resp.Data["allowed_roles"]; ok {
		if err := d.Set("allowed_roles", val); err != nil {
			return fmt.Errorf("error setting state key 'allowed_roles': %s", err)
		}
	}
	if val, ok := resp.Data["masking_character"]; ok {
		if err := d.Set("masking_character", val); err != nil {
			return fmt.Errorf("error setting state key 'masking_character': %s", err)
		}
	}
	if val, ok := resp.Data["template"]; ok {
		if err := d.Set("template", val); err != nil {
			return fmt.Errorf("error setting state key 'template': %s", err)
		}
	}
	if val, ok := resp.Data["templates"]; ok {
		if err := d.Set("templates", val); err != nil {
			return fmt.Errorf("error setting state key 'templates': %s", err)
		}
	}
	if val, ok := resp.Data["tweak_source"]; ok {
		if err := d.Set("tweak_source", val); err != nil {
			return fmt.Errorf("error setting state key 'tweak_source': %s", err)
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
	if raw, ok := d.GetOk("allowed_roles"); ok {
		data["allowed_roles"] = raw
	}
	if raw, ok := d.GetOk("masking_character"); ok {
		data["masking_character"] = raw
	}
	if raw, ok := d.GetOk("template"); ok {
		data["template"] = raw
	}
	if raw, ok := d.GetOk("tweak_source"); ok {
		data["tweak_source"] = raw
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
