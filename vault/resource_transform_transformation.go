// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const transformTransformationEndpoint = "/transform/transformation/{name}"

func transformTransformationResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldPath: {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: `The mount path for a back-end, for example, the path given in "$ vault auth enable -path=my-aws aws".`,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		consts.FieldAllowedRoles: {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Description: `The set of roles allowed to perform this transformation.`,
		},
		consts.FieldMaskingCharacter: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The character used to replace data when in masking mode`,
		},
		consts.FieldName: {
			Type:        schema.TypeString,
			Required:    true,
			Description: `The name of the transformation.`,
			ForceNew:    true,
		},
		consts.FieldTemplate: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The name of the template to use.`,
		},
		consts.FieldTemplates: {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Computed:    true,
			Description: `Templates configured for transformation.`,
		},
		consts.FieldTweakSource: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The source of where the tweak value comes from. Only valid when in FPE mode.`,
		},
		consts.FieldType: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The type of transformation to perform.`,
		},
		consts.FieldDeletionAllowed: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
			Description: `If true, this transform can be deleted. ` +
				`Otherwise deletion is blocked while this value remains false.`,
		},
		consts.FieldMappingMode: {
			Type:        schema.TypeString,
			Optional:    true,
			ForceNew:    true,
			Description: `Specifies the mapping mode for stored values. Only used when type is "tokenization". Cannot be changed after creation.`,
		},
		consts.FieldStores: {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			ForceNew:    true,
			Description: `List of stores to use for tokenization state. Only used when type is "tokenization". Cannot be changed after creation.`,
		},
		consts.FieldConvergent: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `If true, multiple transformations of the same plaintext will produce the same ciphertext. Only used when type is "fpe".`,
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

	path := d.Get(consts.FieldPath).(string)
	vaultPath := util.ParsePath(path, transformTransformationEndpoint, d)
	log.Printf("[DEBUG] Creating %q", vaultPath)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists(consts.FieldAllowedRoles); ok {
		data[consts.FieldAllowedRoles] = v
	}
	if v, ok := d.GetOkExists(consts.FieldMaskingCharacter); ok {
		data[consts.FieldMaskingCharacter] = v
	}
	data[consts.FieldName] = d.Get(consts.FieldName)
	if v, ok := d.GetOkExists(consts.FieldTemplate); ok {
		data[consts.FieldTemplate] = v
	}
	if v, ok := d.GetOkExists(consts.FieldTweakSource); ok {
		data[consts.FieldTweakSource] = v
	}
	if v, ok := d.GetOkExists(consts.FieldType); ok {
		data[consts.FieldType] = v
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		data[consts.FieldDeletionAllowed] = d.Get(consts.FieldDeletionAllowed)
	}

	if v, ok := d.GetOkExists(consts.FieldMappingMode); ok {
		data[consts.FieldMappingMode] = v
	}
	if v, ok := d.GetOkExists(consts.FieldStores); ok {
		data[consts.FieldStores] = v
	}
	if v, ok := d.GetOkExists(consts.FieldConvergent); ok {
		data[consts.FieldConvergent] = v
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
	if val, ok := resp.Data[consts.FieldAllowedRoles]; ok {
		if err := d.Set(consts.FieldAllowedRoles, val); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldAllowedRoles, err)
		}
	}
	if val, ok := resp.Data[consts.FieldMaskingCharacter]; ok {
		if err := d.Set(consts.FieldMaskingCharacter, val); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldMaskingCharacter, err)
		}
	}
	if val, ok := resp.Data[consts.FieldTemplate]; ok {
		if err := d.Set(consts.FieldTemplate, val); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldTemplate, err)
		}
	}
	if val, ok := resp.Data[consts.FieldTemplates]; ok {
		if err := d.Set(consts.FieldTemplates, val); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldTemplates, err)
		}
	}
	if val, ok := resp.Data[consts.FieldTweakSource]; ok {
		if err := d.Set(consts.FieldTweakSource, val); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldTweakSource, err)
		}
	}
	if val, ok := resp.Data[consts.FieldType]; ok {
		if err := d.Set(consts.FieldType, val); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldType, err)
		}
	}
	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		if err := d.Set(consts.FieldDeletionAllowed, resp.Data[consts.FieldDeletionAllowed]); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldDeletionAllowed, err)
		}
	}
	if val, ok := resp.Data[consts.FieldMappingMode]; ok {
		if err := d.Set(consts.FieldMappingMode, val); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldMappingMode, err)
		}
	}
	if val, ok := resp.Data[consts.FieldStores]; ok {
		if err := d.Set(consts.FieldStores, val); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldStores, err)
		}
	}
	if val, ok := resp.Data[consts.FieldConvergent]; ok {
		if err := d.Set(consts.FieldConvergent, val); err != nil {
			return fmt.Errorf("error setting state key %q: %s", consts.FieldConvergent, err)
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
	if raw, ok := d.GetOk(consts.FieldAllowedRoles); ok {
		data[consts.FieldAllowedRoles] = raw
	}
	if raw, ok := d.GetOk(consts.FieldMaskingCharacter); ok {
		data[consts.FieldMaskingCharacter] = raw
	}
	if raw, ok := d.GetOk(consts.FieldTemplate); ok {
		data[consts.FieldTemplate] = raw
	}
	if raw, ok := d.GetOk(consts.FieldTweakSource); ok {
		data[consts.FieldTweakSource] = raw
	}
	if raw, ok := d.GetOk(consts.FieldType); ok {
		data[consts.FieldType] = raw
	}

	if provider.IsAPISupported(meta, provider.VaultVersion112) {
		data[consts.FieldDeletionAllowed] = d.Get(consts.FieldDeletionAllowed)
	}

	if raw, ok := d.GetOk(consts.FieldMappingMode); ok {
		data[consts.FieldMappingMode] = raw
	}
	if raw, ok := d.GetOk(consts.FieldStores); ok {
		data[consts.FieldStores] = raw
	}
	if raw, ok := d.GetOk(consts.FieldConvergent); ok {
		data[consts.FieldConvergent] = raw
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
