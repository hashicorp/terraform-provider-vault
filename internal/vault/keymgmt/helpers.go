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

// Provider type constants
const (
	ProviderAWSKMS  = "awskms"
	ProviderAzureKV = "azurekeyvault"
	ProviderGCPCKMS = "gcpckms"
)

// Error message helper functions
func errCreating(resourceType string, path string, err error) (string, string) {
	return fmt.Sprintf("Error creating %s", resourceType),
		fmt.Sprintf("Error creating %s at %s: %s", resourceType, path, err)
}

func errReading(resourceType string, path string, err error) (string, string) {
	return fmt.Sprintf("Error reading %s", resourceType),
		fmt.Sprintf("Error reading %s at %s: %s", resourceType, path, err)
}

func errUpdating(resourceType string, path string, err error) (string, string) {
	return fmt.Sprintf("Error updating %s", resourceType),
		fmt.Sprintf("Error updating %s at %s: %s", resourceType, path, err)
}

func errDeleting(resourceType string, path string, err error) (string, string) {
	return fmt.Sprintf("Error deleting %s", resourceType),
		fmt.Sprintf("Error deleting %s at %s: %s", resourceType, path, err)
}

// buildKMSPath constructs the Vault API path for KMS provider operations
func buildKMSPath(mountPath, name string) string {
	return fmt.Sprintf("%s/kms/%s", strings.Trim(mountPath, "/"), name)
}

// buildKeyPath constructs the Vault API path for key operations
func buildKeyPath(mountPath, name string) string {
	return fmt.Sprintf("%s/key/%s", strings.Trim(mountPath, "/"), name)
}

// buildDistributeKeyPath constructs the Vault API path for key distribution operations
func buildDistributeKeyPath(mountPath, kmsName, keyName string) string {
	return fmt.Sprintf("%s/kms/%s/key/%s", strings.Trim(mountPath, "/"), kmsName, keyName)
}

// buildReplicateKeyPath constructs the Vault API path for key replication operations
func buildReplicateKeyPath(mountPath, kmsName, keyName string) string {
	return fmt.Sprintf("%s/kms/%s/key/%s/replicate", strings.Trim(mountPath, "/"), kmsName, keyName)
}

// buildKeyRotatePath constructs the Vault API path for key rotation operations
func buildKeyRotatePath(mountPath, name string) string {
	return fmt.Sprintf("%s/key/%s/rotate", strings.Trim(mountPath, "/"), name)
}

// parseKeyPath extracts the mount path and key name from a key API path
// Expected format: <mount_path>/key/<key_name>
func parseKeyPath(apiPath string) (mountPath, keyName string, err error) {
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")
	keyIndex := -1
	for i, part := range parts {
		if part == "key" {
			keyIndex = i
			break
		}
	}

	if keyIndex == -1 || keyIndex+1 >= len(parts) {
		return "", "", fmt.Errorf("invalid key path structure: %s", apiPath)
	}

	mountPath = strings.Join(parts[:keyIndex], "/")
	keyName = parts[keyIndex+1]
	return mountPath, keyName, nil
}

// parseKMSPath extracts the mount path and KMS provider name from a KMS API path
// Expected format: <mount_path>/kms/<kms_name>
func parseKMSPath(apiPath string) (mountPath, kmsName string, err error) {
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")
	kmsIndex := -1
	for i, part := range parts {
		if part == "kms" {
			kmsIndex = i
			break
		}
	}

	if kmsIndex == -1 || kmsIndex+1 >= len(parts) {
		return "", "", fmt.Errorf("invalid KMS path structure: %s", apiPath)
	}

	mountPath = strings.Join(parts[:kmsIndex], "/")
	kmsName = parts[kmsIndex+1]
	return mountPath, kmsName, nil
}

// parseDistributeKeyPath extracts the mount path, KMS name, and key name from a distribution API path
// Expected format: <mount_path>/kms/<kms_name>/key/<key_name>
func parseDistributeKeyPath(apiPath string) (mountPath, kmsName, keyName string, err error) {
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")
	kmsIndex, keyIndex := -1, -1
	for i, part := range parts {
		if part == "kms" {
			kmsIndex = i
		} else if part == "key" && i > kmsIndex {
			keyIndex = i
		}
	}

	if kmsIndex == -1 || keyIndex == -1 || kmsIndex+1 >= len(parts) || keyIndex+1 >= len(parts) {
		return "", "", "", fmt.Errorf("invalid key distribution path structure: %s", apiPath)
	}

	mountPath = strings.Join(parts[:kmsIndex], "/")
	kmsName = parts[kmsIndex+1]
	keyName = parts[keyIndex+1]
	return mountPath, kmsName, keyName, nil
}

// buildAWSCredentialsMap builds a credentials map from either the credentials field or individual access_key/secret_key fields
// Returns nil if no credentials are provided
func buildAWSCredentialsMap(ctx context.Context, credentials types.Map, accessKey, secretKey types.String, diags *diag.Diagnostics) map[string]string {
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

// setInt64FromInterface converts various numeric types from Vault API responses to types.Int64
// Handles json.Number, float64, int, int64, and other numeric types
func setInt64FromInterface(v interface{}) types.Int64 {
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

// setStringFromInterface converts string values from Vault API responses to types.String
// Returns null for empty strings or non-string values
func setStringFromInterface(v interface{}) types.String {
	if str, ok := v.(string); ok && str != "" {
		return types.StringValue(str)
	}
	return types.StringNull()
}
