package transformation

// DO NOT EDIT
// This code is generated.

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

const nameEndpoint = "/transform/transformation/{name}"

func NameResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"path": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Path to backend to configure.",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"allowed_roles": {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Description: "The set of roles allowed to perform this transformation.",
		},
		"masking_character": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The character used to replace data when in masking mode",
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The name of the transformation.",
		},
		"template": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The name of the template to use.",
		},
		"tweak_source": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The source of where the tweak value comes from. Only valid when in FPE mode.",
		},
		"type": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The type of transformation to perform.",
		},
	}
	return &schema.Resource{
		Create: nameCreateResource,
		Update: nameUpdateResource,
		Read:   nameReadResource,
		Exists: nameResourceExists,
		Delete: nameDeleteResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}
func nameCreateResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("path").(string)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists("allowed_roles"); ok {
		data["allowed_roles"] = v
	}
	if v, ok := d.GetOkExists("masking_character"); ok {
		data["masking_character"] = v
	}
	if v, ok := d.GetOkExists("name"); ok {
		data["name"] = v
	}
	if v, ok := d.GetOkExists("template"); ok {
		data["template"] = v
	}
	if v, ok := d.GetOkExists("tweak_source"); ok {
		data["tweak_source"] = v
	}
	if v, ok := d.GetOkExists("type"); ok {
		data["type"] = v
	}

	path := util.ReplacePathParameters(backend+nameEndpoint, d)
	log.Printf("[DEBUG] Writing %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing %q: %s", path, err)
	}
	d.SetId(path)
	log.Printf("[DEBUG] Wrote %q", path)
	return nameReadResource(d, meta)
}

func nameReadResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read %q", path)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	if err := d.Set("allowed_roles", resp.Data["allowed_roles"]); err != nil {
		return fmt.Errorf("error setting state key 'allowed_roles': %s", err)
	}
	if err := d.Set("masking_character", resp.Data["masking_character"]); err != nil {
		return fmt.Errorf("error setting state key 'masking_character': %s", err)
	}
	if err := d.Set("name", resp.Data["name"]); err != nil {
		return fmt.Errorf("error setting state key 'name': %s", err)
	}
	if err := d.Set("template", resp.Data["template"]); err != nil {
		return fmt.Errorf("error setting state key 'template': %s", err)
	}
	if err := d.Set("tweak_source", resp.Data["tweak_source"]); err != nil {
		return fmt.Errorf("error setting state key 'tweak_source': %s", err)
	}
	if err := d.Set("type", resp.Data["type"]); err != nil {
		return fmt.Errorf("error setting state key 'type': %s", err)
	}
	return nil
}

func nameUpdateResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating %q", path)

	data := map[string]interface{}{}
	if d.HasChange("allowed_roles") {
		data["allowed_roles"] = d.Get("allowed_roles")
	}
	if d.HasChange("masking_character") {
		data["masking_character"] = d.Get("masking_character")
	}
	if d.HasChange("name") {
		data["name"] = d.Get("name")
	}
	if d.HasChange("template") {
		data["template"] = d.Get("template")
	}
	if d.HasChange("tweak_source") {
		data["tweak_source"] = d.Get("tweak_source")
	}
	if d.HasChange("type") {
		data["type"] = d.Get("type")
	}
	defer func() {
		d.SetId(path)
	}()
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated %q", path)
	return nameReadResource(d, meta)
}

func nameDeleteResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting %q", path)
	} else if err != nil {
		log.Printf("[DEBUG] %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted template auth backend role %q", path)
	return nil
}

func nameResourceExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return resp != nil, nil
}
