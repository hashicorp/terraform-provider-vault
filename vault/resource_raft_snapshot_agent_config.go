// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var (
	snapshotAutoPath    = "sys/storage/raft/snapshot-auto/config/%s"
	allowedStorageTypes = []string{"local", "azure-blob", "aws-s3", "google-gcs"}
)

func raftSnapshotAgentConfigResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldName: {
			Type:        schema.TypeString,
			ForceNew:    true,
			Description: "Name of the snapshot agent configuration.",
			Required:    true,
		},
		consts.FieldIntervalSeconds: {
			Type:        schema.TypeInt,
			Description: "Number of seconds between snapshots.",
			Required:    true,
		},
		consts.FieldRetain: {
			Type:        schema.TypeInt,
			Description: "How many snapshots are to be kept.",
			Default:     1,
			Optional:    true,
		},
		consts.FieldPathPrefix: {
			Type:        schema.TypeString,
			Description: "The directory or bucket prefix to to use.",
			Required:    true,
		},
		consts.FieldFilePrefix: {
			Type:        schema.TypeString,
			Description: "The file or object name of snapshot files will start with this string.",
			Default:     "vault-snapshot",
			Optional:    true,
		},
		consts.FieldStorageType: {
			Type:         schema.TypeString,
			Description:  "What storage service to send snapshots to. One of \"local\", \"azure-blob\", \"aws-s3\", or \"google-gcs\".",
			Required:     true,
			ForceNew:     true,
			ValidateFunc: storageTypeValidation,
		},
		consts.FieldAutoloadEnabled: {
			Type: schema.TypeBool,
			Description: "Enables automatic restoration of snapshots on cluster initialization or leadership change. " +
				"Requires Vault Enterprise 1.21.0+. Not supported with local storage.",
			Optional: true,
		},
		consts.FieldLocalMaxSpace: {
			Type:        schema.TypeInt,
			Description: "The maximum space, in bytes, to use for snapshots.",
			Optional:    true,
		},
		consts.FieldAWSS3Bucket: {
			Type:        schema.TypeString,
			Description: "S3 bucket to write snapshots to.",
			Optional:    true,
		},
		consts.FieldAWSS3Region: {
			Type:        schema.TypeString,
			Description: "AWS region bucket is in.",
			Optional:    true,
		},
		consts.FieldAWSAccessKeyID: {
			Type:        schema.TypeString,
			Description: "AWS access key ID.",
			Optional:    true,
		},
		consts.FieldAWSSecretAccessKey: {
			Type:        schema.TypeString,
			Description: "AWS secret access key.",
			Optional:    true,
		},
		consts.FieldAWSSessionToken: {
			Type:        schema.TypeString,
			Description: "AWS session token.",
			Optional:    true,
		},
		consts.FieldAWSS3Endpoint: {
			Type:        schema.TypeString,
			Description: "AWS endpoint. This is typically only set when using a non-AWS S3 implementation like Minio.",
			Optional:    true,
		},
		consts.FieldAWSS3DisableTLS: {
			Type:        schema.TypeBool,
			Description: "Disable TLS for the S3 endpoint. This should only be used for testing purposes.",
			Optional:    true,
		},
		consts.FieldAWSS3ForcePathStyle: {
			Type:        schema.TypeBool,
			Description: "Use the endpoint/bucket URL style instead of bucket.endpoint.",
			Optional:    true,
		},
		consts.FieldAWSS3EnableKMS: {
			Type:        schema.TypeBool,
			Description: "Use KMS to encrypt bucket contents.",
			Optional:    true,
		},
		consts.FieldAWSS3ServerSideEncryption: {
			Type:        schema.TypeBool,
			Description: "Use AES256 to encrypt bucket contents.",
			Optional:    true,
		},
		consts.FieldAWSS3KMSKey: {
			Type:        schema.TypeString,
			Description: "Use named KMS key, when aws_s3_enable_kms=true",
			Optional:    true,
		},
		consts.FieldGoogleGCSBucket: {
			Type:        schema.TypeString,
			Description: "GCS bucket to write snapshots to.",
			Optional:    true,
		},
		consts.FieldGoogleServiceAccountKey: {
			Type:        schema.TypeString,
			Description: "Google service account key in JSON format.",
			Optional:    true,
		},
		consts.FieldGoogleEndpoint: {
			Type:        schema.TypeString,
			Description: "GCS endpoint. This is typically only set when using a non-Google GCS implementation like fake-gcs-server.",
			Optional:    true,
		},
		consts.FieldGoogleDisableTLS: {
			Type:        schema.TypeBool,
			Description: "Disable TLS for the GCS endpoint.",
			Optional:    true,
		},
		consts.FieldAzureContainerName: {
			Type:        schema.TypeString,
			Description: "Azure container name to write snapshots to.",
			Optional:    true,
		},
		consts.FieldAzureAccountName: {
			Type:        schema.TypeString,
			Description: "Azure account name.",
			Optional:    true,
		},
		consts.FieldAzureAccountKey: {
			Type:        schema.TypeString,
			Description: "Azure account key. Required when azure_auth_mode is 'shared'.",
			Optional:    true,
		},
		consts.FieldAzureBlobEnvironment: {
			Type:        schema.TypeString,
			Description: "Azure blob environment.",
			Optional:    true,
		},
		consts.FieldAzureEndpoint: {
			Type:        schema.TypeString,
			Description: "Azure blob storage endpoint. This is typically only set when using a non-Azure implementation like Azurite.",
			Optional:    true,
		},
		consts.FieldAzureClientID: {
			Type: schema.TypeString,
			Description: "Azure client ID for authentication. Required when azure_auth_mode is 'managed'. " +
				"Requires Vault Enterprise 1.18.0+.",
			Optional: true,
		},
		consts.FieldAzureAuthMode: {
			Type: schema.TypeString,
			Description: "Azure authentication mode. Required for azure-blob storage. " +
				"Possible values are 'shared', 'managed', or 'environment'. " +
				"Requires Vault Enterprise 1.18.0+.",
			Optional: true,
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

func buildConfigFromResourceData(d *schema.ResourceData, meta interface{}) (map[string]interface{}, error) {
	storageType := d.Get(consts.FieldStorageType).(string)

	data := map[string]interface{}{
		consts.FieldInterval:    d.Get(consts.FieldIntervalSeconds),
		consts.FieldRetain:      d.Get(consts.FieldRetain),
		consts.FieldPathPrefix:  d.Get(consts.FieldPathPrefix),
		consts.FieldFilePrefix:  d.Get(consts.FieldFilePrefix),
		consts.FieldStorageType: d.Get(consts.FieldStorageType),
	}

	// Add autoload_enabled if set and version is supported (Vault 1.21.0+)
	if provider.IsAPISupported(meta, provider.VaultVersion121) {
		if v, ok := d.GetOk(consts.FieldAutoloadEnabled); ok {
			data[consts.FieldAutoloadEnabled] = v
		}
	}

	if storageType == "local" {
		if v, ok := d.GetOk(consts.FieldLocalMaxSpace); ok && v != 0 {
			data[consts.FieldLocalMaxSpace] = v
		} else {
			return nil, errors.New("specified local storage without setting local_max_space")
		}
	}

	if storageType == "aws-s3" {
		if v, ok := d.GetOk(consts.FieldAWSS3Bucket); ok && v != "" {
			data[consts.FieldAWSS3Bucket] = v
		} else {
			return nil, errors.New("specified aws-s3 storage without setting aws_s3_bucket")
		}
		if v, ok := d.GetOk(consts.FieldAWSS3Region); ok && v != "" {
			data[consts.FieldAWSS3Region] = v
		} else {
			return nil, errors.New("specified aws-s3 storage without setting aws_s3_region")
		}
		if v, ok := d.GetOk(consts.FieldAWSAccessKeyID); ok {
			data[consts.FieldAWSAccessKeyID] = v
		}
		if v, ok := d.GetOk(consts.FieldAWSSecretAccessKey); ok {
			data[consts.FieldAWSSecretAccessKey] = v
		}
		if v, ok := d.GetOk(consts.FieldAWSSessionToken); ok {
			data[consts.FieldAWSSessionToken] = v
		}
		if v, ok := d.GetOk(consts.FieldAWSS3Endpoint); ok {
			data[consts.FieldAWSS3Endpoint] = v
		}
		if v, ok := d.GetOk(consts.FieldAWSS3DisableTLS); ok {
			data[consts.FieldAWSS3DisableTLS] = v
		}
		if v, ok := d.GetOk(consts.FieldAWSS3ForcePathStyle); ok {
			data[consts.FieldAWSS3ForcePathStyle] = v
		}
		if v, ok := d.GetOk(consts.FieldAWSS3EnableKMS); ok {
			data[consts.FieldAWSS3EnableKMS] = v
		}
		if v, ok := d.GetOk(consts.FieldAWSS3ServerSideEncryption); ok {
			data[consts.FieldAWSS3ServerSideEncryption] = v
		}
		if v, ok := d.GetOk(consts.FieldAWSS3KMSKey); ok {
			data[consts.FieldAWSS3KMSKey] = v
		}
	}

	if storageType == "google-gcs" {
		if v, ok := d.GetOk(consts.FieldGoogleGCSBucket); ok && v != "" {
			data[consts.FieldGoogleGCSBucket] = v
		} else {
			return nil, errors.New("specified google-gcs storage without setting google_gcs_bucket")
		}
		if v, ok := d.GetOk(consts.FieldGoogleServiceAccountKey); ok {
			data[consts.FieldGoogleServiceAccountKey] = v
		}
		if v, ok := d.GetOk(consts.FieldGoogleEndpoint); ok {
			data[consts.FieldGoogleEndpoint] = v
		}
		if v, ok := d.GetOk(consts.FieldGoogleDisableTLS); ok {
			data[consts.FieldGoogleDisableTLS] = v
		}
	}

	if storageType == "azure-blob" {
		if v, ok := d.GetOk(consts.FieldAzureContainerName); ok && v != "" {
			data[consts.FieldAzureContainerName] = v
		} else {
			return nil, errors.New("specified azure-blob storage without setting azure_container_name")
		}
		if v, ok := d.GetOk(consts.FieldAzureAccountName); ok {
			data[consts.FieldAzureAccountName] = v
		}
		if v, ok := d.GetOk(consts.FieldAzureAccountKey); ok {
			data[consts.FieldAzureAccountKey] = v
		}
		if v, ok := d.GetOk(consts.FieldAzureBlobEnvironment); ok {
			data[consts.FieldAzureBlobEnvironment] = v
		}
		if v, ok := d.GetOk(consts.FieldAzureEndpoint); ok {
			data[consts.FieldAzureEndpoint] = v
		}
		// Add azure_client_id and azure_auth_mode if version is supported (Vault 1.18.0+)
		if provider.IsAPISupported(meta, provider.VaultVersion118) {
			if v, ok := d.GetOk(consts.FieldAzureClientID); ok {
				data[consts.FieldAzureClientID] = v
			}
			if v, ok := d.GetOk(consts.FieldAzureAuthMode); ok {
				data[consts.FieldAzureAuthMode] = v
			}
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

	config, err := buildConfigFromResourceData(d, meta)
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

	if err := d.Set(consts.FieldName, d.Id()); err != nil {
		return fmt.Errorf("error setting state id: %s", err)
	}

	if val, ok := resp.Data[consts.FieldInterval]; ok {
		if err := d.Set(consts.FieldIntervalSeconds, val); err != nil {
			return fmt.Errorf("error setting state key 'interval_seconds': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldRetain]; ok {
		if err := d.Set(consts.FieldRetain, val); err != nil {
			return fmt.Errorf("error setting state key 'retain': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldPathPrefix]; ok {
		if err := d.Set(consts.FieldPathPrefix, val); err != nil {
			return fmt.Errorf("error setting state key 'path_prefix': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldFilePrefix]; ok {
		if err := d.Set(consts.FieldFilePrefix, val); err != nil {
			return fmt.Errorf("error setting state key 'file_prefix': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldStorageType]; ok {
		if err := d.Set(consts.FieldStorageType, val); err != nil {
			return fmt.Errorf("error setting state key 'storage_type': %s", err)
		}
	}

	// Only read autoload_enabled if version is supported (Vault 1.21.0+)
	if provider.IsAPISupported(meta, provider.VaultVersion121) {
		if val, ok := resp.Data[consts.FieldAutoloadEnabled]; ok {
			if err := d.Set(consts.FieldAutoloadEnabled, val); err != nil {
				return fmt.Errorf("error setting state key 'autoload_enabled': %s", err)
			}
		}
	}

	if val, ok := resp.Data[consts.FieldLocalMaxSpace]; ok {
		if err := d.Set(consts.FieldLocalMaxSpace, val); err != nil {
			return fmt.Errorf("error setting state key 'storage_type': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSS3Bucket]; ok {
		if err := d.Set(consts.FieldAWSS3Bucket, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_bucket': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSS3Region]; ok {
		if err := d.Set(consts.FieldAWSS3Region, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_region': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSAccessKeyID]; ok {
		if err := d.Set(consts.FieldAWSAccessKeyID, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_access_key_id': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSSecretAccessKey]; ok {
		if err := d.Set(consts.FieldAWSSecretAccessKey, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_secret_access_key': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSSessionToken]; ok {
		if err := d.Set(consts.FieldAWSSessionToken, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_session_token': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSS3Endpoint]; ok {
		if err := d.Set(consts.FieldAWSS3Endpoint, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_endpoint': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSS3DisableTLS]; ok {
		if err := d.Set(consts.FieldAWSS3DisableTLS, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_disable_tls': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSS3ForcePathStyle]; ok {
		if err := d.Set(consts.FieldAWSS3ForcePathStyle, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_force_path_style': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSS3EnableKMS]; ok {
		if err := d.Set(consts.FieldAWSS3EnableKMS, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_enable_kms': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSS3ServerSideEncryption]; ok {
		if err := d.Set(consts.FieldAWSS3ServerSideEncryption, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_server_side_encryption': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAWSS3KMSKey]; ok {
		if err := d.Set(consts.FieldAWSS3KMSKey, val); err != nil {
			return fmt.Errorf("error setting state key 'aws_s3_kms_key': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldGoogleGCSBucket]; ok {
		if err := d.Set(consts.FieldGoogleGCSBucket, val); err != nil {
			return fmt.Errorf("error setting state key 'google_gcs_bucket': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldGoogleServiceAccountKey]; ok {
		if err := d.Set(consts.FieldGoogleServiceAccountKey, val); err != nil {
			return fmt.Errorf("error setting state key 'google_service_account_key': %s", err)
		}
	}

	// Vault is returning 'false' for this instead of null.
	if val, ok := resp.Data[consts.FieldGoogleEndpoint]; ok && val != false {
		if err := d.Set(consts.FieldGoogleEndpoint, val); err != nil {
			return fmt.Errorf("error setting state key 'google_endpoint': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldGoogleDisableTLS]; ok {
		if err := d.Set(consts.FieldGoogleDisableTLS, val); err != nil {
			return fmt.Errorf("error setting state key 'google_disable_tls': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAzureContainerName]; ok {
		if err := d.Set(consts.FieldAzureContainerName, val); err != nil {
			return fmt.Errorf("error setting state key 'azure_container_name': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAzureAccountName]; ok {
		if err := d.Set(consts.FieldAzureAccountName, val); err != nil {
			return fmt.Errorf("error setting state key 'azure_account_name': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAzureAccountKey]; ok {
		if err := d.Set(consts.FieldAzureAccountKey, val); err != nil {
			return fmt.Errorf("error setting state key 'azure_account_key': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAzureBlobEnvironment]; ok {
		if err := d.Set(consts.FieldAzureBlobEnvironment, val); err != nil {
			return fmt.Errorf("error setting state key 'azure_blob_environment': %s", err)
		}
	}

	if val, ok := resp.Data[consts.FieldAzureEndpoint]; ok {
		if err := d.Set(consts.FieldAzureEndpoint, val); err != nil {
			return fmt.Errorf("error setting state key 'azure_endpoint': %s", err)
		}
	}

	// Only read azure_client_id and azure_auth_mode if version is supported (Vault 1.18.0+)
	if provider.IsAPISupported(meta, provider.VaultVersion118) {
		if val, ok := resp.Data[consts.FieldAzureClientID]; ok {
			if err := d.Set(consts.FieldAzureClientID, val); err != nil {
				return fmt.Errorf("error setting state key 'azure_client_id': %s", err)
			}
		}

		if val, ok := resp.Data[consts.FieldAzureAuthMode]; ok {
			if err := d.Set(consts.FieldAzureAuthMode, val); err != nil {
				return fmt.Errorf("error setting state key 'azure_auth_mode': %s", err)
			}
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
