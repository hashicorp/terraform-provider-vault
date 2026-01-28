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

func keymgmtKeyRotateResource() *schema.Resource {
	return &schema.Resource{
		Create: keymgmtKeyRotateCreate,
		Read:   provider.ReadWrapper(keymgmtKeyRotateRead),
		Delete: keymgmtKeyRotateDelete,
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
				Description: "Name of the key to rotate",
			},
			// Computed fields
			"latest_version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Latest version of the key after rotation",
			},
			"rotation_timestamp": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the key was rotated (RFC3339 format)",
			},
		},
	}
}

func keymgmtKeyRotatePath(path, name string) string {
	return strings.Trim(path, "/") + "/key/" + name + "/rotate"
}

func keymgmtKeyReadPath(path, name string) string {
	return strings.Trim(path, "/") + "/key/" + name
}

func keymgmtKeyRotateCreate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Get(consts.FieldPath).(string)
	name := d.Get(consts.FieldName).(string)

	apiPath := keymgmtKeyRotatePath(path, name)

	log.Printf("[DEBUG] Rotating Key Management key at %s", apiPath)

	// Make POST request to rotate the key
	if _, err := client.Logical().Write(apiPath, map[string]interface{}{}); err != nil {
		return fmt.Errorf("error rotating Key Management key at %s: %w", apiPath, err)
	}

	// Use the key path as the resource ID
	// This allows us to track the rotation event
	keyPath := keymgmtKeyReadPath(path, name)
	d.SetId(keyPath)

	log.Printf("[DEBUG] Successfully rotated Key Management key at %s", apiPath)

	// Read the key details to populate computed fields
	return keymgmtKeyRotateRead(d, meta)
}

func keymgmtKeyRotateRead(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	keyPath := d.Id()

	log.Printf("[DEBUG] Reading Key Management key from %s", keyPath)

	resp, err := client.Logical().Read(keyPath)
	if err != nil {
		return fmt.Errorf("error reading Key Management key at %s: %w", keyPath, err)
	}

	if resp == nil {
		log.Printf("[WARN] Key Management key not found at %s, removing from state", keyPath)
		d.SetId("")
		return nil
	}

	// Parse the path to extract mount path and key name
	parts := strings.Split(strings.Trim(keyPath, "/"), "/")
	if len(parts) < 3 {
		return fmt.Errorf("invalid key path: %s", keyPath)
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

	if keyIndex == -1 || keyIndex >= len(parts)-1 {
		return fmt.Errorf("invalid key path structure: %s", keyPath)
	}

	// Extract mount path and key name
	mountPath := strings.Join(parts[:keyIndex], "/")
	extractedKeyName := parts[keyIndex+1]

	// Set the resource data
	d.Set(consts.FieldPath, mountPath)
	d.Set(consts.FieldName, extractedKeyName)

	// Set computed fields from response
	if v, ok := resp.Data["latest_version"]; ok {
		d.Set("latest_version", v)
	}

	// If timestamp is available, set it
	if v, ok := resp.Data["updated_time"]; ok {
		d.Set("rotation_timestamp", v)
	}

	return nil
}

func keymgmtKeyRotateDelete(d *schema.ResourceData, meta interface{}) error {
	// This is a special case - we don't actually delete the key rotation
	// We just remove it from Terraform state
	// The rotation itself is permanent in Vault

	log.Printf("[DEBUG] Removing key rotation resource from Terraform state (rotation remains in Vault)")
	d.SetId("")

	return nil
}
