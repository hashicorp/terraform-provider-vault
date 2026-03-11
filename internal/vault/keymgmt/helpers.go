// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Error message constants for consistent error reporting
const (
	errInvalidPathStructure = "Invalid path structure"
)

// ResourceType represents a fixed set of resource type labels used in error messages.
type ResourceType string

const (
	ResourceTypeKey             ResourceType = "Key Management key"
	ResourceTypeKeyConfig       ResourceType = "Key Management key config"
	ResourceTypeKeyRotation     ResourceType = "Key Management key rotation"
	ResourceTypeKeyDistribution ResourceType = "Key Management key distribution"
	ResourceTypeKMSProvider     ResourceType = "KMS provider"
	ResourceTypeAWSKMS          ResourceType = "AWS KMS provider"
	ResourceTypeAzureKV         ResourceType = "Azure Key Vault provider"
	ResourceTypeGCPCKMS         ResourceType = "GCP Cloud KMS provider"
)

// Provider type constants
const (
	ProviderAWSKMS  = "awskms"
	ProviderAzureKV = "azurekeyvault"
	ProviderGCPCKMS = "gcpckms"
)

// Error message helper functions

// FormatErrMsg is a common helper that produces the (summary, detail) pair
func FormatErrMsg(action string, resourceType ResourceType, path string, err error) (string, string) {
	return fmt.Sprintf("Error %s %s", action, resourceType),
		fmt.Sprintf("Error %s %s at %s: %s", action, resourceType, path, err)
}

func ErrCreating(resourceType ResourceType, path string, err error) (string, string) {
	return FormatErrMsg("creating", resourceType, path, err)
}

func ErrReading(resourceType ResourceType, path string, err error) (string, string) {
	return FormatErrMsg("reading", resourceType, path, err)
}

func ErrUpdating(resourceType ResourceType, path string, err error) (string, string) {
	return FormatErrMsg("updating", resourceType, path, err)
}

func ErrDeleting(resourceType ResourceType, path string, err error) (string, string) {
	return FormatErrMsg("deleting", resourceType, path, err)
}

// BuildKMSPath constructs the Vault API path for KMS provider operations
func BuildKMSPath(mountPath, name string) string {
	return fmt.Sprintf("%s/kms/%s", strings.Trim(mountPath, "/"), name)
}

// BuildKeyPath constructs the Vault API path for key operations
func BuildKeyPath(mountPath, name string) string {
	return fmt.Sprintf("%s/key/%s", strings.Trim(mountPath, "/"), name)
}

// BuildDistributeKeyPath constructs the Vault API path for key distribution operations
func BuildDistributeKeyPath(mountPath, kmsName, keyName string) string {
	return fmt.Sprintf("%s/kms/%s/key/%s", strings.Trim(mountPath, "/"), kmsName, keyName)
}

// BuildReplicateKeyPath constructs the Vault API path for key replication operations
func BuildReplicateKeyPath(mountPath, kmsName, keyName string) string {
	return fmt.Sprintf("%s/kms/%s/key/%s/replicate", strings.Trim(mountPath, "/"), kmsName, keyName)
}

// BuildKeyRotatePath constructs the Vault API path for key rotation operations
func BuildKeyRotatePath(mountPath, name string) string {
	return fmt.Sprintf("%s/key/%s/rotate", strings.Trim(mountPath, "/"), name)
}

// ParseKeyPath extracts the mount path and key name from a key API path
// Expected format: <mount_path>/key/<key_name>
func ParseKeyPath(apiPath string) (mountPath, keyName string, err error) {
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")

	// Minimum required: 1 mount segment + 2 fixed segments (key/<name>)
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid key path structure: %s", apiPath)
	}

	// Use direct indexing from the end since the format is fixed
	keyIndex := len(parts) - 2

	// Validate the expected segment is in the correct position
	if parts[keyIndex] != "key" {
		return "", "", fmt.Errorf("invalid key path structure: %s", apiPath)
	}

	mountPath = strings.Join(parts[:keyIndex], "/")
	keyName = parts[keyIndex+1]
	return mountPath, keyName, nil
}

// ParseKMSPath extracts the mount path and KMS provider name from a KMS API path
// Expected format: <mount_path>/kms/<kms_name>
func ParseKMSPath(apiPath string) (mountPath, kmsName string, err error) {
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")

	// Minimum required: 1 mount segment + 2 fixed segments (kms/<name>)
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid KMS path structure: %s", apiPath)
	}

	// Use direct indexing from the end since the format is fixed
	kmsIndex := len(parts) - 2

	// Validate the expected segment is in the correct position
	if parts[kmsIndex] != "kms" {
		return "", "", fmt.Errorf("invalid KMS path structure: %s", apiPath)
	}

	mountPath = strings.Join(parts[:kmsIndex], "/")
	kmsName = parts[kmsIndex+1]
	return mountPath, kmsName, nil
}

// ParseDistributeKeyPath extracts the mount path, KMS name, and key name from a distribution API path
// Expected format: <mount_path>/kms/<kms_name>/key/<key_name>
func ParseDistributeKeyPath(apiPath string) (mountPath, kmsName, keyName string, err error) {
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")

	// Minimum required: 1 mount segment + 4 fixed segments (kms/<name>/key/<name>)
	if len(parts) < 5 {
		return "", "", "", fmt.Errorf("invalid key distribution path structure: %s", apiPath)
	}

	// Use direct indexing from the end since the format is fixed
	kmsIndex := len(parts) - 4
	keyIndex := len(parts) - 2

	// Validate the expected segments are in the correct positions
	if parts[kmsIndex] != "kms" || parts[keyIndex] != "key" {
		return "", "", "", fmt.Errorf("invalid key distribution path structure: %s", apiPath)
	}

	mountPath = strings.Join(parts[:kmsIndex], "/")
	kmsName = parts[kmsIndex+1]
	keyName = parts[keyIndex+1]
	return mountPath, kmsName, keyName, nil
}

// BuildAWSCredentialsMap builds a credentials map from either the credentials field or individual access_key/secret_key fields
// Returns nil if no credentials are provided
func BuildAWSCredentialsMap(ctx context.Context, credentials types.Map, accessKey, secretKey types.String, diags *diag.Diagnostics) map[string]string {
	if !credentials.IsNull() {
		var creds map[string]string
		diags.Append(credentials.ElementsAs(ctx, &creds, false)...)
		if diags.HasError() {
			return nil
		}
		return creds
	}

	// Use individual access_key and secret_key if provided
	creds := make(map[string]string)
	if !accessKey.IsNull() {
		creds["access_key"] = accessKey.ValueString()
	}
	if !secretKey.IsNull() {
		creds["secret_key"] = secretKey.ValueString()
	}

	if len(creds) > 0 {
		return creds
	}

	return nil
}

// SetInt64FromInterface converts various numeric types from Vault API responses to types.Int64
// Handles json.Number, float64, int, int64, and other numeric types
func SetInt64FromInterface(v interface{}) types.Int64 {
	switch val := v.(type) {
	case json.Number:
		if vInt, err := val.Int64(); err == nil {
			return types.Int64Value(vInt)
		}
	case float64:
		return types.Int64Value(int64(val))
	case int:
		return types.Int64Value(int64(val))
	case int64:
		return types.Int64Value(val)
	}
	return types.Int64Null()
}

// SetStringFromInterface converts string values from Vault API responses to types.String
// Returns null for empty strings or non-string values
func SetStringFromInterface(v interface{}) types.String {
	if str, ok := v.(string); ok && str != "" {
		return types.StringValue(str)
	}
	return types.StringNull()
}
