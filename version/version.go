// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

// Package version exposes the provider version to the rest of the provider.
package version

import (
	_ "embed"
	"strings"
)

// rawVersion is the contents of the VERSION file, which is the canonical
// source of the provider version. It is read by release.sh at tag time, so
// embedding it here keeps the reported version in sync with releases without
// requiring any build-time linker flags.
//
//go:embed VERSION
var rawVersion string

// ProviderName is the product name the provider identifies itself as to Vault.
// It matches the repository and released binary name.
const ProviderName = "terraform-provider-vault"

// ProviderVersion returns the current provider version, e.g. "5.10.1".
func ProviderVersion() string {
	return strings.TrimSpace(rawVersion)
}
