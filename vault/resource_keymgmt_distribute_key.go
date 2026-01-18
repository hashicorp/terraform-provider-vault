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
)

func keymgmtDistributeKeyResource() *schema.Resource {
	return &schema.Resource{
		Create: keymgmtDistributeKeyCreate,
		Read:   provider.ReadWrapper(keymgmtDistributeKeyRead),
		Update: keymgmtDistributeKeyUpdate,
		Delete: keymgmtDistributeKeyDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				Description:  "Path where the Key Management secrets engine is mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			"kms_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the KMS provider",
			},
			"key_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the key to distribute",
			},
			"purpose": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Purposes for which the key can be used (e.g., encrypt, decrypt, sign, verify)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection level for the key (e.g., hsm, software)",
			},
			// Computed fields
			"key_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the key in the KMS provider",
			},
			"versions": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Versions of the key distributed to the KMS provider",
				Elem:        &schema.Schema{Type: schema.TypeInt},
			},
		},
	}
}

func keymgmtDistributeKeyPath(path, kmsName, keyName string) string {
	return strings.Trim(path, "/") + "/kms/" + kmsName + "/key/" + keyName
}

func keymgmtDistributeKeyCreate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Get(consts.FieldPath).(string)
	kmsName := d.Get("kms_name").(string)
	keyName := d.Get("key_name").(string)
	apiPath := keymgmtDistributeKeyPath(path, kmsName, keyName)

	log.Printf("[DEBUG] Distributing Key Management key to KMS at %s", apiPath)

	data := map[string]interface{}{}

	// Add purpose
	if v, ok := d.GetOk("purpose"); ok {
		purposes := v.(*schema.Set).List()
		purposeStrings := make([]string, len(purposes))
		for i, purpose := range purposes {
			purposeStrings[i] = purpose.(string)
		}
		data["purpose"] = purposeStrings
	}

	// Add protection level
	if v, ok := d.GetOk("protection"); ok {
		data["protection"] = v.(string)
	}

	log.Printf("[DEBUG] Writing Key Management key distribution to %s with data: %+v", apiPath, data)

	if _, err := client.Logical().Write(apiPath, data); err != nil {
		return fmt.Errorf("error distributing Key Management key to KMS at %s: %w", apiPath, err)
	}

	d.SetId(apiPath)

	return keymgmtDistributeKeyRead(d, meta)
}

func keymgmtDistributeKeyRead(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	log.Printf("[DEBUG] Reading Key Management key distribution from %s", apiPath)

	resp, err := client.Logical().Read(apiPath)
	if err != nil {
		return fmt.Errorf("error reading Key Management key distribution at %s: %w", apiPath, err)
	}

	if resp == nil {
		log.Printf("[WARN] Key Management key distribution not found at %s, removing from state", apiPath)
		d.SetId("")
		return nil
	}

	// Parse the path to extract components
	// Path structure: {mount_path}/kms/{kms_name}/key/{key_name}
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")

	// Find the "kms" segment
	kmsIndex := -1
	keyIndex := -1
	for i, part := range parts {
		if part == "kms" {
			kmsIndex = i
		} else if part == "key" && i > kmsIndex {
			keyIndex = i
		}
	}

	if kmsIndex == -1 || keyIndex == -1 || kmsIndex+1 >= len(parts) || keyIndex+1 >= len(parts) {
		return fmt.Errorf("invalid key distribution path structure: %s", apiPath)
	}

	mountPath := strings.Join(parts[:kmsIndex], "/")
	kmsName := parts[kmsIndex+1]
	keyName := parts[keyIndex+1]

	d.Set(consts.FieldPath, mountPath)
	d.Set("kms_name", kmsName)
	d.Set("key_name", keyName)

	if v, ok := resp.Data["purpose"]; ok {
		if purposes, ok := v.([]interface{}); ok {
			purposeSet := schema.NewSet(schema.HashString, purposes)
			d.Set("purpose", purposeSet)
		}
	}

	if v, ok := resp.Data["protection"]; ok {
		d.Set("protection", v)
	}

	if v, ok := resp.Data["key_id"]; ok {
		d.Set("key_id", v)
	}

	if v, ok := resp.Data["versions"]; ok {
		if versions, ok := v.([]interface{}); ok {
			d.Set("versions", versions)
		}
	}

	return nil
}

func keymgmtDistributeKeyUpdate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	log.Printf("[DEBUG] Updating Key Management key distribution at %s", apiPath)

	data := map[string]interface{}{}
	hasChanges := false

	if d.HasChange("purpose") {
		if v, ok := d.GetOk("purpose"); ok {
			purposes := v.(*schema.Set).List()
			purposeStrings := make([]string, len(purposes))
			for i, purpose := range purposes {
				purposeStrings[i] = purpose.(string)
			}
			data["purpose"] = purposeStrings
			hasChanges = true
		}
	}

	if d.HasChange("protection") {
		if v, ok := d.GetOk("protection"); ok {
			data["protection"] = v.(string)
			hasChanges = true
		}
	}

	if hasChanges {
		log.Printf("[DEBUG] Writing Key Management key distribution update to %s with data: %+v", apiPath, data)

		if _, err := client.Logical().Write(apiPath, data); err != nil {
			return fmt.Errorf("error updating Key Management key distribution at %s: %w", apiPath, err)
		}
	}

	return keymgmtDistributeKeyRead(d, meta)
}

func keymgmtDistributeKeyDelete(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	log.Printf("[DEBUG] Deleting Key Management key distribution at %s", apiPath)

	if _, err := client.Logical().Delete(apiPath); err != nil {
		return fmt.Errorf("error deleting Key Management key distribution at %s: %w", apiPath, err)
	}

	return nil
}
