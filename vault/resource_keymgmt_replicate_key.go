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

func keymgmtReplicateKeyResource() *schema.Resource {
	return &schema.Resource{
		Create: keymgmtReplicateKeyCreate,
		Read:   provider.ReadWrapper(keymgmtReplicateKeyRead),
		Delete: keymgmtReplicateKeyDelete,
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
				Description: "Name of the key to replicate",
			},
		},
	}
}

func keymgmtReplicateKeyPath(path, kmsName, keyName string) string {
	return strings.Trim(path, "/") + "/kms/" + kmsName + "/key/" + keyName + "/replicate"
}

func keymgmtReplicateKeyKeyPath(path, keyName string) string {
	return strings.Trim(path, "/") + "/key/" + keyName
}

func keymgmtReplicateKeyCreate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Get(consts.FieldPath).(string)
	kmsName := d.Get("kms_name").(string)
	keyName := d.Get("key_name").(string)

	// First, validate that the KMS provider is AWS
	kmsPath := strings.Trim(path, "/") + "/kms/" + kmsName
	log.Printf("[DEBUG] Validating KMS provider at %s", kmsPath)

	kmsResp, err := client.Logical().Read(kmsPath)
	if err != nil {
		return fmt.Errorf("error reading KMS provider at %s: %w", kmsPath, err)
	}

	if kmsResp == nil {
		return fmt.Errorf("KMS provider %s not found at %s", kmsName, kmsPath)
	}

	// Check if KMS provider is AWS
	kmsProvider := ""
	if v, ok := kmsResp.Data["provider"]; ok {
		kmsProvider = v.(string)
	}

	if kmsProvider != "awskms" {
		return fmt.Errorf("key replication is only supported for AWS KMS providers. Current provider: %s", kmsProvider)
	}

	// Validate that the key has replica_regions configured
	keyPath := keymgmtReplicateKeyKeyPath(path, keyName)
	log.Printf("[DEBUG] Validating key configuration at %s", keyPath)

	keyResp, err := client.Logical().Read(keyPath)
	if err != nil {
		return fmt.Errorf("error reading Key Management key at %s: %w", keyPath, err)
	}

	if keyResp == nil {
		return fmt.Errorf("key %s not found at %s", keyName, keyPath)
	}

	// Check if replica_regions is set and not empty
	hasReplicaRegions := false
	if v, ok := keyResp.Data["replica_regions"]; ok {
		if regions, ok := v.([]interface{}); ok && len(regions) > 0 {
			hasReplicaRegions = true
		}
	}

	if !hasReplicaRegions {
		return fmt.Errorf("cannot replicate key %s: replica_regions must be configured in vault_keymgmt_key resource before replication", keyName)
	}

	// Proceed with replication
	apiPath := keymgmtReplicateKeyPath(path, kmsName, keyName)
	log.Printf("[DEBUG] Replicating Key Management key at %s", apiPath)

	if _, err := client.Logical().Write(apiPath, map[string]interface{}{}); err != nil {
		return fmt.Errorf("error replicating Key Management key at %s: %w", apiPath, err)
	}

	// Use a custom ID that includes all components
	d.SetId(apiPath)

	return keymgmtReplicateKeyRead(d, meta)
}

func keymgmtReplicateKeyRead(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	// Parse the path to extract components
	// Path structure: {mount_path}/kms/{kms_name}/key/{key_name}/replicate
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")

	// Find the "kms" and "key" segments
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
		return fmt.Errorf("invalid replication path structure: %s", apiPath)
	}

	mountPath := strings.Join(parts[:kmsIndex], "/")
	kmsName := parts[kmsIndex+1]
	keyName := parts[keyIndex+1]

	d.Set(consts.FieldPath, mountPath)
	d.Set("kms_name", kmsName)
	d.Set("key_name", keyName)

	// Verify the key distribution still exists
	distPath := strings.Trim(mountPath, "/") + "/kms/" + kmsName + "/key/" + keyName
	log.Printf("[DEBUG] Verifying key distribution exists at %s", distPath)

	resp, err := client.Logical().Read(distPath)
	if err != nil {
		return fmt.Errorf("error reading Key Management key distribution at %s: %w", distPath, err)
	}

	if resp == nil {
		log.Printf("[WARN] Key Management key distribution not found at %s, removing replication from state", distPath)
		d.SetId("")
		return nil
	}

	return nil
}

func keymgmtReplicateKeyDelete(d *schema.ResourceData, meta interface{}) error {
	// Replication is not a physical resource that can be deleted
	// Removing it from Terraform state is sufficient
	// The replicated keys remain in the KMS provider regions
	log.Printf("[DEBUG] Removing Key Management key replication from state (no API deletion needed)")

	return nil
}
