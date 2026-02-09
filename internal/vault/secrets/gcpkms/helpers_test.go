// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms_test

import (
	"os"
)

const (
	// Environment variable names for GCP KMS testing
	envVarGoogleCredentials = "GOOGLE_CREDENTIALS"
	envVarGoogleKMSKeyRing  = "GOOGLE_KMS_KEY_RING"
)

// getMockGCPCredentials returns GCP credentials from env var or empty string
func getMockGCPCredentials() string {
	return os.Getenv(envVarGoogleCredentials)
}

// getMockKeyRing returns GCP KMS key ring from env var or empty string
func getMockKeyRing() string {
	return os.Getenv(envVarGoogleKMSKeyRing)
}
