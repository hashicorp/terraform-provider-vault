// Copyright IBM Corp. 2016, 2025
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

const (
	transformTemplateEndpoint = "/transform/template/{name}"

	// schema field names
	pathField          = "path"
	alphabetField      = "alphabet"
	nameField          = "name"
	patternField       = "pattern"
	typeField          = "type"
	encodeFormatField  = "encode_format"
	decodeFormatsField = "decode_formats"
)

var requestFields = []string{
	pathField,
	alphabetField,
	nameField,
	patternField,
	typeField,
	encodeFormatField,
	decodeFormatsField,
}

func transformTemplateResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		pathField: {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: `The mount path for a back-end, for example, the path given in "$ vault auth enable -path=my-aws aws".`,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		alphabetField: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The alphabet to use for this template. This is only used during FPE transformations.`,
		},
		nameField: {
			Type:        schema.TypeString,
			Required:    true,
			Description: `The name of the template.`,
			ForceNew:    true,
		},
		patternField: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The pattern used for matching. Currently, only regular expression pattern is supported.`,
		},
		typeField: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The pattern type to use for match detection. Currently, only regex is supported.`,
		},
		encodeFormatField: {
			Type:     schema.TypeString,
			Optional: true,
			Description: `The regular expression template used for encoding values.
Only applicable to FPE transformations.`,
		},
		decodeFormatsField: {
			Type:     schema.TypeMap,
			Optional: true,
			Description: `The map of regular expression templates used to customize decoded outputs.
Only applicable to FPE transformations.`,
		},
	}
	return &schema.Resource{
		Create: createTransformTemplateResource,
		Update: updateTransformTemplateResource,
		Read:   provider.ReadWrapper(readTransformTemplateResource),
		Exists: resourceTransformTemplateExists,
		Delete: deleteTransformTemplateResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func createTransformTemplateResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Get("path").(string)
	vaultPath := util.ParsePath(path, transformTemplateEndpoint, d)
	log.Printf("[DEBUG] Creating %q", vaultPath)

	log.Printf("[DEBUG] Writing %q", vaultPath)
	if _, err := client.Logical().Write(vaultPath, requestData(d, requestFields)); err != nil {
		return fmt.Errorf("error writing %q: %s", vaultPath, err)
	}
	d.SetId(vaultPath)
	log.Printf("[DEBUG] Wrote %q", vaultPath)
	return readTransformTemplateResource(d, meta)
}

func readTransformTemplateResource(d *schema.ResourceData, meta interface{}) error {
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
	pathParams, err := util.PathParameters(transformTemplateEndpoint, vaultPath)
	if err != nil {
		return err
	}
	for paramName, paramVal := range pathParams {
		if err := d.Set(paramName, paramVal); err != nil {
			return fmt.Errorf("error setting state %q, %q: %s", paramName, paramVal, err)
		}
	}

	for _, field := range requestFields {
		if val, ok := resp.Data[field]; ok {
			if err := d.Set(field, val); err != nil {
				return fmt.Errorf("error setting state key %q: %s", field, err)
			}
		}
	}

	return nil
}

func updateTransformTemplateResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	vaultPath := d.Id()
	log.Printf("[DEBUG] Updating %q", vaultPath)

	if _, err := client.Logical().Write(vaultPath, requestData(d, requestFields)); err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", vaultPath, err)
	}

	log.Printf("[DEBUG] Updated %q", vaultPath)
	return readTransformTemplateResource(d, meta)
}

func requestData(d *schema.ResourceData, fields []string) map[string]interface{} {
	data := make(map[string]interface{})
	for _, field := range fields {
		if raw, ok := d.GetOk(field); ok {
			data[field] = raw
		}
	}
	return data
}

func deleteTransformTemplateResource(d *schema.ResourceData, meta interface{}) error {
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

func resourceTransformTemplateExists(d *schema.ResourceData, meta interface{}) (bool, error) {
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
