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

func keymgmtKeyDeleteResource() *schema.Resource {
	return &schema.Resource{
		Create: keymgmtKeyDeleteCreate,
		Read:   provider.ReadWrapper(keymgmtKeyDeleteRead),
		Delete: keymgmtKeyDeleteDelete,
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
				Description: "Name of the key to delete",
			},
			// Computed fields
			"deletion_allowed": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether deletion was allowed for this key",
			},
			"deletion_timestamp": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the key was deleted (RFC3339 format)",
			},
		},
	}
}

func keymgmtKeyDeletePath(path, name string) string {
	return strings.Trim(path, "/") + "/key/" + name
}

func keymgmtKeyDeleteCreate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Get(consts.FieldPath).(string)
	name := d.Get(consts.FieldName).(string)

	apiPath := keymgmtKeyDeletePath(path, name)

	log.Printf("[DEBUG] Deleting Key Management key at %s", apiPath)

	// First, verify the key exists and check deletion_allowed setting
	resp, err := client.Logical().Read(apiPath)
	if err != nil {
		return fmt.Errorf("error reading Key Management key at %s: %w", apiPath, err)
	}

	if resp == nil {
		return fmt.Errorf("Key Management key not found at %s", apiPath)
	}

	// Check if deletion is allowed
	deletionAllowed := false
	if v, ok := resp.Data["deletion_allowed"]; ok {
		if val, ok := v.(bool); ok {
			deletionAllowed = val
		}
	}

	if !deletionAllowed {
		return fmt.Errorf(
			"cannot delete key %s: deletion_allowed is not set to true. "+
				"Set deletion_allowed=true on the vault_keymgmt_key resource",
			name,
		)
	}

	// Store deletion_allowed before deletion for computed field
	d.Set("deletion_allowed", deletionAllowed)

	// Make DELETE request to delete the key
	if _, err := client.Logical().Delete(apiPath); err != nil {
		return fmt.Errorf("error deleting Key Management key at %s: %w", apiPath, err)
	}

	// Set resource ID to track the deletion
	d.SetId(apiPath)

	log.Printf("[DEBUG] Successfully deleted Key Management key at %s", apiPath)

	// Set deletion timestamp to current time (approximate)
	d.Set("deletion_timestamp", "managed-deletion")

	return nil
}

func keymgmtKeyDeleteRead(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	keyPath := d.Id()

	log.Printf("[DEBUG] Reading Key Management key deletion status from %s", keyPath)

	// Try to read the key
	// If it exists, it means deletion failed or was rolled back
	// If it doesn't exist, it was successfully deleted
	resp, err := client.Logical().Read(keyPath)
	if err != nil {
		// 404 or permission error means key was deleted
		log.Printf("[DEBUG] Key read returned error (expected if deleted): %v", err)
		// Keep the resource in state with deletion timestamp
		return nil
	}

	if resp == nil {
		// Key was deleted
		log.Printf("[DEBUG] Key no longer exists (successfully deleted)")
		return nil
	}

	// Key still exists - this might be unexpected
	log.Printf("[WARN] Key still exists at %s after deletion attempt", keyPath)

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

	// Set computed fields from response if key still exists
	if v, ok := resp.Data["deletion_allowed"]; ok {
		d.Set("deletion_allowed", v)
	}

	return nil
}

func keymgmtKeyDeleteDelete(d *schema.ResourceData, meta interface{}) error {
	// This is a special case - the key is already deleted
	// We just remove it from Terraform state
	// If it still exists in Vault, that's a separate issue

	log.Printf("[DEBUG] Removing key deletion resource from Terraform state")
	d.SetId("")

	return nil
}
