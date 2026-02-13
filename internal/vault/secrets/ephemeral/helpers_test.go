// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"os"
	"regexp"
)

const (
	// Environment variable names for GCP KMS testing
	envVarGoogleCredentials = "GOOGLE_CREDENTIALS"
	envVarGoogleKMSKeyRing  = "GOOGLE_KMS_KEY_RING"
)

var (
	// Common regex patterns used across GCP KMS ephemeral tests
	regexpBase64   = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	regexpNonEmpty = regexp.MustCompile(`.+`)
)

// getMockGCPCredentials returns GCP credentials from env var or empty string
func getMockGCPCredentials() string {
	return os.Getenv(envVarGoogleCredentials)
}

// getMockKeyRing returns GCP KMS key ring from env var or empty string
func getMockKeyRing() string {
	return os.Getenv(envVarGoogleKMSKeyRing)
}
