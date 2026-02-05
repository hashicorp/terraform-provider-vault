// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"strings"
)

// buildKMSPath constructs the Vault API path for KMS provider operations
func buildKMSPath(mountPath, name string) string {
	return strings.Trim(mountPath, "/") + "/kms/" + name
}

// buildKeyPath constructs the Vault API path for key operations
func buildKeyPath(mountPath, name string) string {
	return strings.Trim(mountPath, "/") + "/key/" + name
}
