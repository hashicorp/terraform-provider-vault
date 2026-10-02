// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"fmt"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// checkVaultVersion verifies that the Vault server version is at least 2.0.0
// which is required for PKI External CA features.
func checkVaultVersion(meta *provider.ProviderMeta) error {
	minVersion := provider.VaultVersion200
	currentVersion := meta.GetVaultVersion()

	if !meta.IsAPISupported(minVersion) {
		return fmt.Errorf("PKI External CA features require Vault version %s or higher; current version: %s",
			minVersion, currentVersion)
	}

	return nil
}

// checkVaultVersionDNS verifies that the Vault server version is at least 2.1.0
// which is required for PKI External CA DNS provider configuration.
func checkVaultVersionDNS(meta *provider.ProviderMeta) error {
	minVersion := provider.VaultVersion210
	currentVersion := meta.GetVaultVersion()

	if !meta.IsAPISupported(minVersion) {
		return fmt.Errorf("PKI External CA DNS provider configuration requires Vault version %s or higher; current version: %s",
			minVersion, currentVersion)
	}

	return nil
}
