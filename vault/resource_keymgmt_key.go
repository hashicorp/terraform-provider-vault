// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func keymgmtKeyResource() *schema.Resource {
	return &schema.Resource{
		Create: keymgmtKeyCreate,
		Read:   provider.ReadWrapper(keymgmtKeyRead),
		Update: keymgmtKeyUpdate,
		Delete: keymgmtKeyDelete,
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
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the key",
			},
			consts.FieldType: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "Type of the key. Valid values are: aes256-gcm96, rsa-2048, rsa-3072, rsa-4096, " +
					"ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519, hmac",
			},
			"deletion_allowed": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If set to true, the key can be deleted. Defaults to false",
			},
			"allow_plaintext_backup": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If set to true, plaintext backup of the key is allowed. Defaults to false",
			},
			"allow_generate_key": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "If set to true, allows generating a new key in supported KMS providers. Defaults to true",
			},
			"replica_regions": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of regions where the key should be replicated. AWS KMS only.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			// Computed fields
			"latest_version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Latest version of the key",
			},
			"min_enabled_version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Minimum enabled version of the key",
			},
			"distribution": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of KMS providers where this key is distributed",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"kms": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Name of the KMS provider",
						},
					},
				},
			},
		},
	}
}

func keymgmtKeyPath(path, name string) string {
	return strings.Trim(path, "/") + "/key/" + name
}

func keymgmtKeyCreate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Get(consts.FieldPath).(string)
	name := d.Get(consts.FieldName).(string)
	apiPath := keymgmtKeyPath(path, name)

	log.Printf("[DEBUG] Creating Key Management key at %s", apiPath)

	// Create endpoint only supports type and replica_regions
	data := map[string]interface{}{
		"type": d.Get(consts.FieldType).(string),
	}

	if v, ok := d.GetOk("replica_regions"); ok {
		regions := v.(*schema.Set).List()
		regionStrings := make([]string, len(regions))
		for i, region := range regions {
			regionStrings[i] = region.(string)
		}
		data["replica_regions"] = strings.Join(regionStrings, ",")
	}

	log.Printf("[DEBUG] Writing Key Management key to %s with data: %+v", apiPath, data)

	if _, err := client.Logical().Write(apiPath, data); err != nil {
		return fmt.Errorf("error creating Key Management key at %s: %w", apiPath, err)
	}

	d.SetId(apiPath)

	// Give Vault time to register the key before applying config updates
	// This is necessary because KMS requires the key to exist before applying config
	time.Sleep(500 * time.Millisecond)

	// Apply configuration parameters that can only be set via update
	configData := map[string]interface{}{}

	if v, ok := d.GetOk("deletion_allowed"); ok {
		configData["deletion_allowed"] = v.(bool)
	}

	if v, ok := d.GetOk("allow_plaintext_backup"); ok {
		configData["allow_plaintext_backup"] = v.(bool)
	}

	if v, ok := d.GetOk("allow_generate_key"); ok {
		configData["allow_generate_key"] = v.(bool)
	}

	if len(configData) > 0 {
		log.Printf("[DEBUG] Updating Key Management key config at %s with data: %+v", apiPath, configData)
		if _, err := client.Logical().Write(apiPath, configData); err != nil {
			return fmt.Errorf("error updating Key Management key config at %s: %w", apiPath, err)
		}
	}

	return keymgmtKeyRead(d, meta)
}

func keymgmtKeyRead(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	log.Printf("[DEBUG] Reading Key Management key from %s", apiPath)

	resp, err := client.Logical().Read(apiPath)
	if err != nil {
		return fmt.Errorf("error reading Key Management key at %s: %w", apiPath, err)
	}

	if resp == nil {
		log.Printf("[WARN] Key Management key not found at %s, removing from state", apiPath)
		d.SetId("")
		return nil
	}

	// Parse the path to extract mount path and key name
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")
	if len(parts) < 3 {
		return fmt.Errorf("invalid key path: %s", apiPath)
	}

	// The path structure is: {mount_path}/key/{key_name}
	// Find the "key" segment
	keyIndex := -1
	for i, part := range parts {
		if part == "key" {
			keyIndex = i
			break
		}
	}

	if keyIndex == -1 || keyIndex+1 >= len(parts) {
		return fmt.Errorf("invalid key path structure: %s", apiPath)
	}

	mountPath := strings.Join(parts[:keyIndex], "/")
	keyName := parts[keyIndex+1]

	d.Set(consts.FieldPath, mountPath)
	d.Set(consts.FieldName, keyName)

	if v, ok := resp.Data["type"]; ok {
		d.Set(consts.FieldType, v)
	}

	if v, ok := resp.Data["deletion_allowed"]; ok {
		d.Set("deletion_allowed", v)
	}

	if v, ok := resp.Data["allow_plaintext_backup"]; ok {
		d.Set("allow_plaintext_backup", v)
	}

	if v, ok := resp.Data["allow_generate_key"]; ok {
		d.Set("allow_generate_key", v)
	}

	if v, ok := resp.Data["latest_version"]; ok {
		switch version := v.(type) {
		case json.Number:
			if vInt, err := version.Int64(); err == nil {
				d.Set("latest_version", int(vInt))
			}
		case float64:
			d.Set("latest_version", int(version))
		case int:
			d.Set("latest_version", version)
		}
	}

	if v, ok := resp.Data["min_enabled_version"]; ok {
		switch version := v.(type) {
		case json.Number:
			if vInt, err := version.Int64(); err == nil {
				d.Set("min_enabled_version", int(vInt))
			}
		case float64:
			d.Set("min_enabled_version", int(version))
		case int:
			d.Set("min_enabled_version", version)
		}
	}

	if v, ok := resp.Data["distribution"]; ok {
		if distributions, ok := v.([]interface{}); ok {
			distList := make([]map[string]interface{}, 0, len(distributions))
			for _, dist := range distributions {
				if distMap, ok := dist.(map[string]interface{}); ok {
					distList = append(distList, map[string]interface{}{
						"kms": distMap["kms"],
					})
				}
			}
			d.Set("distribution", distList)
		}
	}

	return nil
}

func keymgmtKeyUpdate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	log.Printf("[DEBUG] Updating Key Management key at %s", apiPath)

	data := map[string]interface{}{}

	if d.HasChange("deletion_allowed") {
		data["deletion_allowed"] = d.Get("deletion_allowed").(bool)
	}

	if d.HasChange("allow_plaintext_backup") {
		data["allow_plaintext_backup"] = d.Get("allow_plaintext_backup").(bool)
	}

	if d.HasChange("allow_generate_key") {
		data["allow_generate_key"] = d.Get("allow_generate_key").(bool)
	}

	if len(data) > 0 {
		log.Printf("[DEBUG] Updating Key Management key at %s with data: %+v", apiPath, data)

		if _, err := client.Logical().Write(apiPath, data); err != nil {
			return fmt.Errorf("error updating Key Management key at %s: %w", apiPath, err)
		}
	}

	return keymgmtKeyRead(d, meta)
}

func keymgmtKeyDelete(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	log.Printf("[DEBUG] Deleting Key Management key at %s", apiPath)

	if _, err := client.Logical().Delete(apiPath); err != nil {
		return fmt.Errorf("error deleting Key Management key at %s: %w", apiPath, err)
	}

	return nil
}
