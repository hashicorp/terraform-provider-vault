// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	snapshotAutoPath    = "sys/storage/raft/snapshot-auto/config/%s"
	allowedStorageTypes = []string{"local", "azure-blob", "aws-s3", "google-gcs"}
)

func raftSnapshotAgentConfigResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			ForceNew:    true,
			Description: "Name of the snapshot agent configuration.",
			Required:    true,
		},
		"interval_seconds": {
			Type:        schema.TypeInt,
			Description: "Number of seconds between snapshots.",
			Required:    true,
		},
		"retain": {
			Type:        schema.TypeInt,
			Description: "How many snapshots are to be kept.",
			Default:     1,
			Optional:    true,
		},
		"path_prefix": {
			Type:        schema.TypeString,
			Description: "The directory or bucket prefix to to use.",
			Required:    true,
		},
		"file_prefix": {
			Type:        schema.TypeString,
			Description: "The file or object name of snapshot files will start with this string.",
			Default:     "vault-snapshot",
			Optional:    true,
		},
		"storage_type": {
			Type:         schema.TypeString,
			Description:  "What storage service to send snapshots to. One of \"local\", \"azure-blob\", \"aws-s3\", or \"google-gcs\".",
			Required:     true,
			ForceNew:     true,
			ValidateFunc: storageTypeValidation,
		},
		"autoload_enabled": {
			Type:        schema.TypeBool,
			Description: "Enables automatic restoration of snapshots on cluster initialization or leadership change.",
			Optional:    true,
			Default:     false,
		},
		"local_max_space": {
			Type:        schema.TypeInt,
			Description: "The maximum space, in bytes, to use for snapshots.",
			Optional:    true,
		},
		"aws_s3_bucket": {
			Type:        schema.TypeString,
			Description: "S3 bucket to write snapshots to.",
			Optional:    true,
		},
		"aws_s3_region": {
			Type:        schema.TypeString,
			Description: "AWS region bucket is in.",
			Optional:    true,
		},
		"aws_access_key_id": {
			Type:        schema.TypeString,
			Description: "AWS access key ID.",
			Optional:    true,
		},
		"aws_secret_access_key": {
			Type:        schema.TypeString,
			Description: "AWS secret access key.",
			Optional:    true,
		},
		"aws_session_token": {
			Type:        schema.TypeString,
			Description: "AWS session token.",
			Optional:    true,
		},
		"aws_s3_endpoint": {
			Type:        schema.TypeString,
			Description: "AWS endpoint. This is typically only set when using a non-AWS S3 implementation like Minio.",
			Optional:    true,
		},
		"aws_s3_disable_tls": {
			Type:        schema.TypeBool,
			Description: "Disable TLS for the S3 endpoint. This should only be used for testing purposes.",
			Optional:    true,
		},
		"aws_s3_force_path_style": {
			Type:        schema.TypeBool,
			Description: "Use the endpoint/bucket URL style instead of bucket.endpoint.",
			Optional:    true,
		},
		"aws_s3_enable_kms": {
			Type:        schema.TypeBool,
			Description: "Use KMS to encrypt bucket contents.",
			Optional:    true,
		},
		"aws_s3_server_side_encryption": {
			Type:        schema.TypeBool,
			Description: "Use AES256 to encrypt bucket contents.",
			Optional:    true,
		},
		"aws_s3_kms_key": {
			Type:        schema.TypeString,
			Description: "Use named KMS key, when aws_s3_enable_kms=true",
			Optional:    true,
		},
		"google_gcs_bucket": {
			Type:        schema.TypeString,
			Description: "GCS bucket to write snapshots to.",
			Optional:    true,
		},
		"google_service_account_key": {
			Type:        schema.TypeString,
			Description: "Google service account key in JSON format.",
			Optional:    true,
		},
		"google_endpoint": {
			Type:        schema.TypeString,
			Description: "GCS endpoint. This is typically only set when using a non-Google GCS implementation like fake-gcs-server.",
			Optional:    true,
		},
		"google_disable_tls": {
			Type:        schema.TypeBool,
			Description: "Disable TLS for the GCS endpoint.",
			Optional:    true,
		},
		"azure_container_name": {
			Type:        schema.TypeString,
			Description: "Azure container name to write snapshots to.",
			Optional:    true,
		},
		"azure_account_name": {
			Type:        schema.TypeString,
			Description: "Azure account name.",
			Optional:    true,
		},
		"azure_account_key": {
			Type:        schema.TypeString,
			Description: "Azure account key. Required when azure_auth_mode is 'shared'.",
			Optional:    true,
		},
		"azure_blob_environment": {
			Type:        schema.TypeString,
			Description: "Azure blob environment.",
			Optional:    true,
		},
		"azure_endpoint": {
			Type:        schema.TypeString,
			Description: "Azure blob storage endpoint. This is typically only set when using a non-Azure implementation like Azurite.",
			Optional:    true,
		},
		"azure_client_id": {
			Type:        schema.TypeString,
			Description: "Azure client ID for authentication. Required when azure_auth_mode is 'managed'.",
			Optional:    true,
		},
		"azure_auth_mode": {
			Type:        schema.TypeString,
			Description: "Azure authentication mode. Required for azure-blob storage. Possible values are 'shared', 'managed', or 'environment'.",
			Optional:    true,
		},
	}
	return &schema.Resource{
		Create: createOrUpdateSnapshotAgentConfigResource,
		Update: createOrUpdateSnapshotAgentConfigResource,
		Read:   provider.ReadWrapper(readSnapshotAgentConfigResource),
		Delete: deleteSnapshotAgentConfigResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func storageTypeValidation(val interface{}, key string) ([]string, []error) {
	v := val.(string)
	for _, storageType := range allowedStorageTypes {
		if v == storageType {
			return nil, nil
		}
	}
	return nil, []error{fmt.Errorf("%q must be one of [\"local\", \"azure-blob\", \"aws-s3\", \"google-gcs\"], got: %s", key, v)}
}

func buildConfigFromResourceData(d *schema.ResourceData) (map[string]interface{}, error) {
	storageType := d.Get("storage_type").(string)

	data := map[string]interface{}{
		"interval":     d.Get("interval_seconds"),
		"retain":       d.Get("retain"),
		"path_prefix":  d.Get("path_prefix"),
		"file_prefix":  d.Get("file_prefix"),
		"storage_type": d.Get("storage_type"),
	}

	// Add autoload_enabled if set
	if v, ok := d.GetOk("autoload_enabled"); ok {
		data["autoload_enabled"] = v
	}

	if storageType == "local" {
		if v, ok := d.GetOk("local_max_space"); ok && v != 0 {
			data["local_max_space"] = v
		} else {
			return nil, errors.New("specified local storage without setting local_max_space")
		}
	}

	if storageType == "aws-s3" {
		if v, ok := d.GetOk("aws_s3_bucket"); ok && v != "" {
			data["aws_s3_bucket"] = v
		} else {
			return nil, errors.New("specified aws-s3 storage without setting aws_s3_bucket")
		}
		if v, ok := d.GetOk("aws_s3_region"); ok && v != "" {
			data["aws_s3_region"] = v
		} else {
			return nil, errors.New("specified aws-s3 storage without setting aws_s3_region")
		}
		if v, ok := d.GetOk("aws_access_key_id"); ok {
			data["aws_access_key_id"] = v
		}
		if v, ok := d.GetOk("aws_secret_access_key"); ok {
			data["aws_secret_access_key"] = v
		}
		if v, ok := d.GetOk("aws_session_token"); ok {
			data["aws_session_token"] = v
		}
		if v, ok := d.GetOk("aws_s3_endpoint"); ok {
			data["aws_s3_endpoint"] = v
		}
		if v, ok := d.GetOk("aws_s3_disable_tls"); ok {
			data["aws_s3_disable_tls"] = v
		}
		if v, ok := d.GetOk("aws_s3_force_path_style"); ok {
			data["aws_s3_force_path_style"] = v
		}
		if v, ok := d.GetOk("aws_s3_enable_kms"); ok {
			data["aws_s3_enable_kms"] = v
		}
		if v, ok := d.GetOk("aws_s3_server_side_encryption"); ok {
			data["aws_s3_server_side_encryption"] = v
		}
		if v, ok := d.GetOk("aws_s3_kms_key"); ok {
			data["aws_s3_kms_key"] = v
		}
	}

	if storageType == "google-gcs" {
		if v, ok := d.GetOk("google_gcs_bucket"); ok && v != "" {
			data["google_gcs_bucket"] = v
		} else {
			return nil, errors.New("specified google-gcs storage without setting google_gcs_bucket")
		}
		if v, ok := d.GetOk("google_service_account_key"); ok {
			data["google_service_account_key"] = v
		}
		if v, ok := d.GetOk("google_endpoint"); ok {
			data["google_endpoint"] = v
		}
		if v, ok := d.GetOk("google_disable_tls"); ok {
			data["google_disable_tls"] = v
		}
	}

	if storageType == "azure-blob" {
		if v, ok := d.GetOk("azure_container_name"); ok && v != "" {
			data["azure_container_name"] = v
		} else {
			return nil, errors.New("specified azure-blob storage without setting azure_container_name")
		}
		if v, ok := d.GetOk("azure_account_name"); ok {
			data["azure_account_name"] = v
		}
		if v, ok := d.GetOk("azure_account_key"); ok {
			data["azure_account_key"] = v
		}
		if v, ok := d.GetOk("azure_blob_environment"); ok {
			data["azure_blob_environment"] = v
		}
		if v, ok := d.GetOk("azure_endpoint"); ok {
			data["azure_endpoint"] = v
		}
		if v, ok := d.GetOk("azure_client_id"); ok {
			data["azure_client_id"] = v
		}
		if v, ok := d.GetOk("azure_auth_mode"); ok {
			data["azure_auth_mode"] = v
		}
	}
	return data, nil
}

func createOrUpdateSnapshotAgentConfigResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)
	path := fmt.Sprintf(snapshotAutoPath, name)

	config, err := buildConfigFromResourceData(d)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Configuring automatic snapshots: %q", name)
	if _, err = client.Logical().Write(path, config); err != nil {
		return fmt.Errorf("error writing %q: %s", path, err)
	}
	log.Printf("[DEBUG] Configured automatic snapshots: %q", name)
	d.SetId(name)

	return readSnapshotAgentConfigResource(d, meta)
}

func readSnapshotAgentConfigResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	configPath := fmt.Sprintf(snapshotAutoPath, name)
	log.Printf("[DEBUG] Reading %q", configPath)

	resp, err := client.Logical().Read(configPath)
	if resp == nil || (err != nil && util.Is404(err)) {
		log.Printf("[WARN] %q not found, removing from state", name)
		d.SetId("")
		return nil
	}
	if err != nil {
		return fmt.Errorf("error reading %q: %s", configPath, err)
	}

	if err := d.Set("name", d.Id()); err != nil {
		return fmt.Errorf("error setting state id: %s", err)
	}

	if val, ok := resp.Data["interval"]; ok {
		if err := d.Set("interval_seconds", val); err != nil {
			return fmt.Errorf("error setting state key 'interval_seconds': %s", err)
		}
	}

	if val, ok := resp.Data["retain"]; ok {
		if err := d.Set("retain", val); err != nil {
			return fmt.Errorf("error setting state key 'retain': %s", err)
		}
	}

	if val, ok := resp.Data["path_prefix"]; ok {
		if err := d.Set("path_prefix", val); err != nil {
			return fmt.Errorf("error setting state key 'path_prefix': %s", err)
		}
	}

	if val, ok := resp.Data["file_prefix"]; ok {
		if err := d.Set("file_prefix", val); err != nil {
			return fmt.Errorf("error setting state key 'file_prefix': %s", err)
		}
	}

	if val, ok := resp.Data["storage_type"]; ok {
		if err := d.Set("storage_type", val); err != nil {
			return fmt.Errorf("error setting state key 'storage_type': %s", err)
		}
	}

	if val, ok := resp.Data["autoload_enabled"]; ok {
		if err := d.Set("autoload_enabled", val); err != nil {
			return fmt.Errorf("error setting state key 'autoload_enabled': %s", err)
		}
	}

	if val, ok := resp.Data["local_max_space"]; ok {
		if err := d.Set("local_max_space", val); err != nil {
			return fmt.Errorf("error setting state key 'storage_type': %s", err)
		}
	}

	if val, ok := resp.Data["aws_s3_bucket"]; ok {
		if err := d.Set("aws_s3_bucket", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_bucket': %s", err)
		}
	}

	if val, ok := resp.Data["aws_s3_region"]; ok {
		if err := d.Set("aws_s3_region", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_region': %s", err)
		}
	}

	if val, ok := resp.Data["aws_access_key_id"]; ok {
		if err := d.Set("aws_access_key_id", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_access_key_id': %s", err)
		}
	}

	if val, ok := resp.Data["aws_secret_access_key"]; ok {
		if err := d.Set("aws_secret_access_key", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_secret_access_key': %s", err)
		}
	}

	if val, ok := resp.Data["aws_session_token"]; ok {
		if err := d.Set("aws_session_token", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_session_token': %s", err)
		}
	}

	if val, ok := resp.Data["aws_s3_endpoint"]; ok {
		if err := d.Set("aws_s3_endpoint", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_endpoint': %s", err)
		}
	}

	if val, ok := resp.Data["aws_s3_disable_tls"]; ok {
		if err := d.Set("aws_s3_disable_tls", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_disable_tls': %s", err)
		}
	}

	if val, ok := resp.Data["aws_s3_force_path_style"]; ok {
		if err := d.Set("aws_s3_force_path_style", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_force_path_style': %s", err)
		}
	}

	if val, ok := resp.Data["aws_s3_enable_kms"]; ok {
		if err := d.Set("aws_s3_enable_kms", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_enable_kms': %s", err)
		}
	}

	if val, ok := resp.Data["aws_s3_server_side_encryption"]; ok {
		if err := d.Set("aws_s3_server_side_encryption", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_server_side_encryption': %s", err)
		}
	}

	if val, ok := resp.Data["aws_s3_kms_key"]; ok {
		if err := d.Set("aws_s3_kms_key", val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_kms_key': %s", err)
		}
	}

	if val, ok := resp.Data["google_gcs_bucket"]; ok {
		if err := d.Set("google_gcs_bucket", val); err != nil {
			return fmt.Errorf("error setting state key 'google_gcs_bucket': %s", err)
		}
	}

	if val, ok := resp.Data["google_service_account_key"]; ok {
		if err := d.Set("google_service_account_key", val); err != nil {
			return fmt.Errorf("error setting state key 'google_service_account_key': %s", err)
		}
	}

	// Vault is returning 'false' for this instead of null.
	if val, ok := resp.Data["google_endpoint"]; ok && val != false {
		if err := d.Set("google_endpoint", val); err != nil {
			return fmt.Errorf("error setting state key 'google_endpoint': %s", err)
		}
	}

	if val, ok := resp.Data["google_disable_tls"]; ok {
		if err := d.Set("google_disable_tls", val); err != nil {
			return fmt.Errorf("error setting state key 'google_disable_tls': %s", err)
		}
	}

	if val, ok := resp.Data["azure_container_name"]; ok {
		if err := d.Set("azure_container_name", val); err != nil {
			return fmt.Errorf("error setting state key 'azure_container_name': %s", err)
		}
	}

	if val, ok := resp.Data["azure_account_name"]; ok {
		if err := d.Set("azure_account_name", val); err != nil {
			return fmt.Errorf("error setting state key 'azure_account_name': %s", err)
		}
	}

	if val, ok := resp.Data["azure_account_key"]; ok {
		if err := d.Set("azure_account_key", val); err != nil {
			return fmt.Errorf("error setting state key 'azure_account_key': %s", err)
		}
	}

	if val, ok := resp.Data["azure_blob_environment"]; ok {
		if err := d.Set("azure_blob_environment", val); err != nil {
			return fmt.Errorf("error setting state key 'azure_blob_environment': %s", err)
		}
	}

	if val, ok := resp.Data["azure_endpoint"]; ok {
		if err := d.Set("azure_endpoint", val); err != nil {
			return fmt.Errorf("error setting state key 'azure_endpoint': %s", err)
		}
	}

	if val, ok := resp.Data["azure_client_id"]; ok {
		if err := d.Set("azure_client_id", val); err != nil {
			return fmt.Errorf("error setting state key 'azure_client_id': %s", err)
		}
	}

	if val, ok := resp.Data["azure_auth_mode"]; ok {
		if err := d.Set("azure_auth_mode", val); err != nil {
			return fmt.Errorf("error setting state key 'azure_auth_mode': %s", err)
		}
	}

	return nil
}

func deleteSnapshotAgentConfigResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Id()
	path := fmt.Sprintf(snapshotAutoPath, name)

	log.Printf("[DEBUG] Removing Raft Snapshot Agent Config: %q", name)

	_, err := client.Logical().Delete(path)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", name)
		d.SetId("")
		return fmt.Errorf("error removing raft snapshot agent config from %q: %s", path, err)
	} else if err != nil {
		return fmt.Errorf("error removing raft snapshot agent config from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Removed raft snapshot agent config: %q", name)
	return nil
}
