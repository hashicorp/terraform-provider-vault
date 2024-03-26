// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const transformTransformationEndpoint = "/transform/transformation/{name}"

func transformTransformationResource() *schema.Resource {
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
		"deletion_allowed": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
			Description: `If true, this transform can be deleted. ` +
				`Otherwise deletion is blocked while this value remains false.`,
		},
	}
	return &schema.Resource{
		Create: createTransformTransformationResource,
		Update: updateTransformTransformationResource,
		Read:   provider.ReadWrapper(readTransformTransformationResource),
		Exists: resourceTransformTransformationExists,
		Delete: deleteTransformTransformationResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func createTransformTransformationResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Get("path").(string)
	vaultPath := util.ParsePath(path, transformTransformationEndpoint, d)
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

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		data["deletion_allowed"] = d.Get("deletion_allowed")
	}

	log.Printf("[DEBUG] Writing %q", vaultPath)
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", vaultPath, err)
	}
	d.SetId(vaultPath)
	log.Printf("[DEBUG] Wrote %q", vaultPath)
	return readTransformTransformationResource(d, meta)
}

func readTransformTransformationResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

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
	pathParams, err := util.PathParameters(transformTransformationEndpoint, vaultPath)
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
	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if err := d.Set("deletion_allowed", resp.Data["deletion_allowed"]); err != nil {
			return fmt.Errorf("error setting state key 'deletion_allowed': %s", err)
		}
	}
	return nil
}

func updateTransformTransformationResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

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

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		data["deletion_allowed"] = d.Get("deletion_allowed")
	}

	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", vaultPath, err)
	}

	log.Printf("[DEBUG] Updated %q", vaultPath)
	return readTransformTransformationResource(d, meta)
}

func deleteTransformTransformationResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
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

func resourceTransformTransformationExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}
	vaultPath := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", vaultPath)

	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", vaultPath)
	return resp != nil, nil
}
