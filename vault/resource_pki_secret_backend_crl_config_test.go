// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func getCRLConfigChecks(resourceName string, isUpdate, unifiedCrl bool, maxCrlEntries int) resource.TestCheckFunc {
	baseChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "expiry", "72h"),
		resource.TestCheckResourceAttr(resourceName, "disable", "true"),
	}

	v112BaseChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "ocsp_disable", "false"),
		resource.TestCheckResourceAttr(resourceName, "ocsp_expiry", "12h"),
		resource.TestCheckResourceAttr(resourceName, "auto_rebuild", "true"),
		resource.TestCheckResourceAttr(resourceName, "auto_rebuild_grace_period", "12h"),
		resource.TestCheckResourceAttr(resourceName, "enable_delta", "true"),
		resource.TestCheckResourceAttr(resourceName, "delta_rebuild_interval", "15m"),
	}

	v112UpdateChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "ocsp_disable", "false"),
		resource.TestCheckResourceAttr(resourceName, "ocsp_expiry", "23h"),
		resource.TestCheckResourceAttr(resourceName, "auto_rebuild", "true"),
		resource.TestCheckResourceAttr(resourceName, "auto_rebuild_grace_period", "24h"),
		resource.TestCheckResourceAttr(resourceName, "enable_delta", "true"),
		resource.TestCheckResourceAttr(resourceName, "delta_rebuild_interval", "18m"),
	}

	v113BaseChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "cross_cluster_revocation", "false"),
		resource.TestCheckResourceAttr(resourceName, "unified_crl", "false"),
		resource.TestCheckResourceAttr(resourceName, "unified_crl_on_existing_paths", "false"),
	}

	v113UpdateChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "cross_cluster_revocation", strconv.FormatBool(unifiedCrl)),
		resource.TestCheckResourceAttr(resourceName, "unified_crl", strconv.FormatBool(unifiedCrl)),
		resource.TestCheckResourceAttr(resourceName, "unified_crl_on_existing_paths", strconv.FormatBool(unifiedCrl)),
	}

	v119Checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "max_crl_entries", strconv.FormatInt(int64(maxCrlEntries), 10)),
	}

	return func(state *terraform.State) error {
		var checks []resource.TestCheckFunc
		meta := testProvider.Meta().(*provider.ProviderMeta)
		isVaultVersion112 := meta.IsAPISupported(provider.VaultVersion112)
		isVaultVersion113 := meta.IsAPISupported(provider.VaultVersion113)
		isVaultVersion119 := meta.IsAPISupported(provider.VaultVersion119)

		checks = baseChecks
		if isVaultVersion112 {
			if !isUpdate {
				checks = append(checks, v112BaseChecks...)
			} else {
				checks = append(checks, v112UpdateChecks...)
			}
		}
		if isVaultVersion113 {
			if !isUpdate {
				checks = append(checks, v113BaseChecks...)
			} else {
				checks = append(checks, v113UpdateChecks...)
			}
		}
		if isVaultVersion119 {
			checks = append(checks, v119Checks...)
		}

		return resource.ComposeAggregateTestCheckFunc(checks...)(state)
	}
}

func TestPkiSecretBackendCrlConfig(t *testing.T) {
	// test against vault-1.11 and below
	t.Run("vault-1.11-and-below", func(t *testing.T) {
		setupCRLConfigTest(t, func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionGTE(t, testProvider.Meta(), provider.VaultVersion112)
		},
			"ocsp_disable",
			"ocsp_expiry",
			"auto_rebuild",
			"auto_rebuild_grace_period",
			"enable_delta",
			"delta_rebuild_interval",
			"cross_cluster_revocation",
			"unified_crl",
			"unified_crl_on_existing_paths",
			"max_crl_entries",
		)
	})

	// test against vault-1.12
	t.Run("vault-1.12", func(t *testing.T) {
		setupCRLConfigTest(t, func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionGTE(t, testProvider.Meta(), provider.VaultVersion113)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
			"cross_cluster_revocation",
			"unified_crl",
			"unified_crl_on_existing_paths",
			"max_crl_entries",
		)
	})

	// test against vault-1.13 up to and including 1.18
	t.Run("vault-1.13-to-1.18", func(t *testing.T) {
		setupCRLConfigTest(t, func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion113)
			SkipIfAPIVersionGTE(t, testProvider.Meta(), provider.VaultVersion119)
		},
			"max_crl_entries",
		)
	})

	// test against vault-1.19 and above
	t.Run("vault-1.19-and-above", func(t *testing.T) {
		setupCRLConfigTest(t, func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		)
	})
}

func setupCRLConfigTest(t *testing.T, preCheck func(), ignoreImportFields ...string) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	resourceName := "vault_pki_secret_backend_crl_config.test"
	var unifiedCrl bool
	if os.Getenv(testutil.EnvVarTfAccEnt) != "" {
		unifiedCrl = true
	}
	meta := testProvider.Meta().(*provider.ProviderMeta)
	steps := []resource.TestStep{
		{
			Config: testPkiSecretBackendCrlConfigConfig_defaults(rootPath),
			Check:  getCRLConfigChecks(resourceName, false, unifiedCrl, 100000),
		},
		{
			Config: testPkiSecretBackendCrlConfigConfig_explicit(rootPath, unifiedCrl, 100),
			Check:  getCRLConfigChecks(resourceName, true, unifiedCrl, 100),
		},
	}
	if meta.IsAPISupported(provider.VaultVersion112) {
		steps = append(steps, resource.TestStep{
			Config: testPkiSecretBackendCrlConfigConfig_autoRebuildDisabled(rootPath, unifiedCrl, 50),
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "auto_rebuild", "false"),
			),
		})
	}
	steps = append(steps, testutil.GetImportTestStep(resourceName, false, nil, ignoreImportFields...))
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 preCheck,
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps:                    steps,
	})
}

func testPkiSecretBackendCrlConfigConfig_base(rootPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds     = "8640000"
}

resource "vault_pki_secret_backend_root_cert" "test-ca" {
  backend            = vault_mount.test-root.path
  type               = "internal"
  common_name        = "test-ca.example.com"
  ttl                = "8640000"
  format             = "pem"
  private_key_format = "der"
  key_type           = "rsa"
  key_bits           = 4096
  ou                 = "Test OU"
  organization       = "ACME Ltd"
}
`, rootPath)
}

func testPkiSecretBackendCrlConfigConfig_defaults(rootPath string) string {
	return fmt.Sprintf(`
%s

resource "vault_pki_secret_backend_crl_config" "test" {
  backend      = vault_pki_secret_backend_root_cert.test-ca.backend
  expiry       = "72h"
  disable      = true
  ocsp_disable = false
  ocsp_expiry = "12h"
  auto_rebuild = true
  enable_delta = true
}
`, testPkiSecretBackendCrlConfigConfig_base(rootPath))
}

func testPkiSecretBackendCrlConfigConfig_explicit(rootPath string, unifiedCrl bool, maxCrlEntries int) string {
	return fmt.Sprintf(`
%[1]s

resource "vault_pki_secret_backend_crl_config" "test" {
  backend                   	= vault_pki_secret_backend_root_cert.test-ca.backend
  expiry                    	= "72h"
  disable                   	= true
  ocsp_disable              	= false
  ocsp_expiry               	= "23h"
  auto_rebuild              	= true
  auto_rebuild_grace_period 	= "24h"
  enable_delta              	= true
  delta_rebuild_interval   		= "18m"
  cross_cluster_revocation  	= %[2]s
  unified_crl					= %[2]s
  unified_crl_on_existing_paths = %[2]s
  max_crl_entries				= %[3]d
}
`, testPkiSecretBackendCrlConfigConfig_base(rootPath), strconv.FormatBool(unifiedCrl), maxCrlEntries)
}

func testPkiSecretBackendCrlConfigConfig_autoRebuildDisabled(rootPath string, unifiedCrl bool, maxCrlEntries int) string {
	return fmt.Sprintf(`
%[1]s

resource "vault_pki_secret_backend_crl_config" "test" {
  backend                       = vault_pki_secret_backend_root_cert.test-ca.backend
  expiry                        = "72h"
  disable                       = true
  ocsp_disable                  = false
  ocsp_expiry                   = "23h"
  auto_rebuild                  = false
  enable_delta                  = true
  delta_rebuild_interval        = "18m"
  cross_cluster_revocation      = %[2]s
  unified_crl                   = %[2]s
  unified_crl_on_existing_paths = %[2]s
  max_crl_entries               = %[3]d
}
`, testPkiSecretBackendCrlConfigConfig_base(rootPath), strconv.FormatBool(unifiedCrl), maxCrlEntries)
}
