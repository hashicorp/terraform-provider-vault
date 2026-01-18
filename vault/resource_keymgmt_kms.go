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

func keymgmtKmsResource() *schema.Resource {
	return &schema.Resource{
		Create: keymgmtKmsCreate,
		Read:   provider.ReadWrapper(keymgmtKmsRead),
		Update: keymgmtKmsUpdate,
		Delete: keymgmtKmsDelete,
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
				Description: "Name of the KMS provider",
			},
			"kms_provider": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Type of the KMS provider. Valid values are: awskms, azurekeyvault, gcpckms",
			},
			"key_collection": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The collection or region where keys are stored (e.g., AWS region, Azure key vault name)",
			},
			"credentials": {
				Type:        schema.TypeMap,
				Optional:    true,
				Sensitive:   true,
				Description: "Credentials for authenticating to the KMS provider",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			// AWS-specific fields
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS region (for AWS KMS provider)",
			},
			// Azure-specific fields
			"tenant_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure tenant ID (for Azure Key Vault provider)",
			},
			"client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure client ID (for Azure Key Vault provider)",
			},
			"client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Azure client secret (for Azure Key Vault provider)",
			},
			"environment": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure environment (for Azure Key Vault provider)",
			},
			// GCP-specific fields
			"service_account_file": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "GCP service account JSON (for GCP Cloud KMS provider)",
			},
			"project": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GCP project (for GCP Cloud KMS provider)",
			},
			"location": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GCP location (for GCP Cloud KMS provider)",
			},
			// Computed fields
			"uuid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "UUID of the KMS provider",
			},
		},
	}
}

func keymgmtKmsPath(path, name string) string {
	return strings.Trim(path, "/") + "/kms/" + name
}

func keymgmtKmsCreate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Get(consts.FieldPath).(string)
	name := d.Get(consts.FieldName).(string)
	apiPath := keymgmtKmsPath(path, name)

	log.Printf("[DEBUG] Creating Key Management KMS provider at %s", apiPath)

	data := map[string]interface{}{
		"provider":       d.Get("kms_provider").(string),
		"key_collection": d.Get("key_collection").(string),
	}

	// Add provider-specific configuration
	providerType := d.Get("kms_provider").(string)

	// Handle credentials map
	if v, ok := d.GetOk("credentials"); ok {
		credMap := v.(map[string]interface{})
		data["credentials"] = credMap
	}

	// AWS-specific fields
	if providerType == "awskms" {
		if v, ok := d.GetOk("region"); ok {
			data["region"] = v.(string)
		}
	}

	// Azure-specific fields
	if providerType == "azurekeyvault" {
		if v, ok := d.GetOk("tenant_id"); ok {
			data["tenant_id"] = v.(string)
		}
		if v, ok := d.GetOk("client_id"); ok {
			data["client_id"] = v.(string)
		}
		if v, ok := d.GetOk("client_secret"); ok {
			data["client_secret"] = v.(string)
		}
		if v, ok := d.GetOk("environment"); ok {
			data["environment"] = v.(string)
		}
	}

	// GCP-specific fields
	if providerType == "gcpckms" {
		if v, ok := d.GetOk("service_account_file"); ok {
			data["service_account_file"] = v.(string)
		}
		if v, ok := d.GetOk("project"); ok {
			data["project"] = v.(string)
		}
		if v, ok := d.GetOk("location"); ok {
			data["location"] = v.(string)
		}
	}

	log.Printf("[DEBUG] Writing Key Management KMS provider to %s", apiPath)

	if _, err := client.Logical().Write(apiPath, data); err != nil {
		return fmt.Errorf("error creating Key Management KMS provider at %s: %w", apiPath, err)
	}

	d.SetId(apiPath)

	return keymgmtKmsRead(d, meta)
}

func keymgmtKmsRead(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	log.Printf("[DEBUG] Reading Key Management KMS provider from %s", apiPath)

	resp, err := client.Logical().Read(apiPath)
	if err != nil {
		return fmt.Errorf("error reading Key Management KMS provider at %s: %w", apiPath, err)
	}

	if resp == nil {
		log.Printf("[WARN] Key Management KMS provider not found at %s, removing from state", apiPath)
		d.SetId("")
		return nil
	}

	// Parse the path to extract mount path and KMS name
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")
	if len(parts) < 3 {
		return fmt.Errorf("invalid KMS path: %s", apiPath)
	}

	// The path structure is: {mount_path}/kms/{kms_name}
	// Find the "kms" segment
	kmsIndex := -1
	for i, part := range parts {
		if part == "kms" {
			kmsIndex = i
			break
		}
	}

	if kmsIndex == -1 || kmsIndex+1 >= len(parts) {
		return fmt.Errorf("invalid KMS path structure: %s", apiPath)
	}

	mountPath := strings.Join(parts[:kmsIndex], "/")
	kmsName := parts[kmsIndex+1]

	d.Set(consts.FieldPath, mountPath)
	d.Set(consts.FieldName, kmsName)

	if v, ok := resp.Data["provider"]; ok {
		d.Set("kms_provider", v)
	}

	if v, ok := resp.Data["key_collection"]; ok {
		d.Set("key_collection", v)
	}

	if v, ok := resp.Data["uuid"]; ok {
		d.Set("uuid", v)
	}

	// Provider-specific fields - only set if they exist
	if v, ok := resp.Data["region"]; ok {
		d.Set("region", v)
	}

	if v, ok := resp.Data["tenant_id"]; ok {
		d.Set("tenant_id", v)
	}

	if v, ok := resp.Data["client_id"]; ok {
		d.Set("client_id", v)
	}

	if v, ok := resp.Data["environment"]; ok {
		d.Set("environment", v)
	}

	if v, ok := resp.Data["project"]; ok {
		d.Set("project", v)
	}

	if v, ok := resp.Data["location"]; ok {
		d.Set("location", v)
	}

	// Note: Sensitive fields like credentials, client_secret, and service_account_file
	// are not returned by the API, so we don't update them here

	return nil
}

func keymgmtKmsUpdate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	log.Printf("[DEBUG] Updating Key Management KMS provider at %s", apiPath)

	data := map[string]interface{}{}
	hasChanges := false

	if d.HasChange("key_collection") {
		data["key_collection"] = d.Get("key_collection").(string)
		hasChanges = true
	}

	if d.HasChange("credentials") {
		if v, ok := d.GetOk("credentials"); ok {
			data["credentials"] = v.(map[string]interface{})
			hasChanges = true
		}
	}

	providerType := d.Get("kms_provider").(string)

	// AWS-specific updates
	if providerType == "awskms" && d.HasChange("region") {
		data["region"] = d.Get("region").(string)
		hasChanges = true
	}

	// Azure-specific updates
	if providerType == "azurekeyvault" {
		if d.HasChange("tenant_id") {
			data["tenant_id"] = d.Get("tenant_id").(string)
			hasChanges = true
		}
		if d.HasChange("client_id") {
			data["client_id"] = d.Get("client_id").(string)
			hasChanges = true
		}
		if d.HasChange("client_secret") {
			data["client_secret"] = d.Get("client_secret").(string)
			hasChanges = true
		}
		if d.HasChange("environment") {
			data["environment"] = d.Get("environment").(string)
			hasChanges = true
		}
	}

	// GCP-specific updates
	if providerType == "gcpckms" {
		if d.HasChange("service_account_file") {
			data["service_account_file"] = d.Get("service_account_file").(string)
			hasChanges = true
		}
		if d.HasChange("project") {
			data["project"] = d.Get("project").(string)
			hasChanges = true
		}
		if d.HasChange("location") {
			data["location"] = d.Get("location").(string)
			hasChanges = true
		}
	}

	if hasChanges {
		// Need to include provider again for update
		data["provider"] = providerType

		log.Printf("[DEBUG] Writing Key Management KMS provider update to %s", apiPath)

		if _, err := client.Logical().Write(apiPath, data); err != nil {
			return fmt.Errorf("error updating Key Management KMS provider at %s: %w", apiPath, err)
		}
	}

	return keymgmtKmsRead(d, meta)
}

func keymgmtKmsDelete(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	apiPath := d.Id()

	log.Printf("[DEBUG] Deleting Key Management KMS provider at %s", apiPath)

	if _, err := client.Logical().Delete(apiPath); err != nil {
		return fmt.Errorf("error deleting Key Management KMS provider at %s: %w", apiPath, err)
	}

	return nil
}
