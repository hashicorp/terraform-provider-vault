// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func getCRLConfigChecks(resourceName string, isUpdate bool) resource.TestCheckFunc {
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
		resource.TestCheckResourceAttr(resourceName, "cross_cluster_revocation", "true"),
		resource.TestCheckResourceAttr(resourceName, "unified_crl", "true"),
		resource.TestCheckResourceAttr(resourceName, "unified_crl_on_existing_paths", "true"),
	}

	return func(state *terraform.State) error {
		var checks []resource.TestCheckFunc
		meta := testProvider.Meta().(*provider.ProviderMeta)
		isVaultVersion113 := meta.IsAPISupported(provider.VaultVersion113)
		isVaultVersion112 := meta.IsAPISupported(provider.VaultVersion112)
		switch {
		case isVaultVersion113:
			if !isUpdate {
				checks = append(checks, v113BaseChecks...)
				checks = append(checks, v112BaseChecks...)
			} else {
				checks = append(checks, v113UpdateChecks...)
				checks = append(checks, v112UpdateChecks...)
			}
		case isVaultVersion112:
			if !isUpdate {
				checks = append(checks, v112BaseChecks...)
			} else {
				checks = append(checks, v112UpdateChecks...)
			}
		default:
			checks = baseChecks
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
		)
	})

	// test against vault-1.13 and above
	t.Run("vault-1.13-and-above", func(t *testing.T) {
		setupCRLConfigTest(t, func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion113)
		},
		)
	})
}

func setupCRLConfigTest(t *testing.T, preCheck func(), ignoreImportFields ...string) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	resourceName := "vault_pki_secret_backend_crl_config.test"
	steps := []resource.TestStep{
		{
			Config: testPkiSecretBackendCrlConfigConfig_defaults(rootPath),
			Check:  getCRLConfigChecks(resourceName, false),
		},
		{
			SkipFunc: func() (bool, error) {
				_, found := os.LookupEnv(testutil.EnvVarTfAccEnt)
				return !found, nil
			},
			Config: testPkiSecretBackendCrlConfigConfig_explicit(rootPath),
			Check:  getCRLConfigChecks(resourceName, true),
		},
		testutil.GetImportTestStep(resourceName, false, nil, ignoreImportFields...),
	}
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          preCheck,
		CheckDestroy:      testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps:             steps,
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

func testPkiSecretBackendCrlConfigConfig_explicit(rootPath string) string {
	return fmt.Sprintf(`
%s

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
  cross_cluster_revocation  	= true
  unified_crl					= true
  unified_crl_on_existing_paths = true
}
`, testPkiSecretBackendCrlConfigConfig_base(rootPath))
}
