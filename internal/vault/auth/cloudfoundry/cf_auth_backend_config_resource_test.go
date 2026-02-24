// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudfoundry_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// cfTestParams holds the configurable CF server details used across test steps.
// Values are resolved from environment variables at test start so all steps
// share the same CA cert and credentials.
type cfTestParams struct {
	// apiAddr is the address of the CF API (e.g. "http://127.0.0.1:52072").
	apiAddr string
	// username / password are the CF API credentials Vault will use.
	username string
	password string
	// ca is the PEM-encoded CA certificate that signed the CF instance certs,
	// stored as identity_ca_certificates.
	ca string
}

// cfTestParamsFromEnv resolves test parameters from environment variables:
//
//   - CF_TEST_CA_CERT_FILE – path to a PEM CA cert file (identity_ca_certificates).
//   - CF_TEST_API_ADDR    – CF API address (cf_api_addr).
//   - CF_TEST_USERNAME    – CF username (cf_username).
//   - CF_TEST_PASSWORD    – CF password (cf_password_wo).
//
// When none of the above are set the function falls back to a locally-generated
// CA cert and placeholder values that are sufficient for config-write/read
// tests (Vault stores the values without contacting the CF API).
func cfTestParamsFromEnv(t *testing.T) cfTestParams {
	t.Helper()

	var ca string

	if certFile := os.Getenv("CF_TEST_CA_CERT_FILE"); certFile != "" {
		certBytes, err := os.ReadFile(certFile)
		if err != nil {
			t.Fatalf("CF_TEST_CA_CERT_FILE is set but cannot read file %s: %s", certFile, err)
		}
		ca = strings.TrimSpace(string(certBytes))
	} else {
		// Fall back to a generated CA cert – valid PEM, accepted by Vault's CF
		// auth plugin for config write/read without contacting the real CF API.
		caBytes, _, err := testutil.GenerateCA()
		if err != nil {
			t.Fatalf("failed to generate CA cert: %s", err)
		}
		ca = strings.TrimSpace(string(caBytes))
	}

	apiAddr := os.Getenv("CF_TEST_API_ADDR")
	if apiAddr == "" {
		apiAddr = "https://api.example.com"
	}

	username := os.Getenv("CF_TEST_USERNAME")
	if username == "" {
		username = "admin"
	}

	password := os.Getenv("CF_TEST_PASSWORD")
	if password == "" {
		password = "password123"
	}

	return cfTestParams{
		apiAddr:  apiAddr,
		username: username,
		password: password,
		ca:       ca,
	}
}

// TestAccCFAuthBackendConfig tests full CRUD lifecycle and import for
// the vault_cf_auth_backend_config resource.
func TestAccCFAuthBackendConfig(t *testing.T) {
	mount := acctest.RandomWithPrefix("cf-mount")
	resourceAddress := "vault_cf_auth_backend_config.test"

	params := cfTestParamsFromEnv(t)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create basic config with only required fields.
			{
				Config: testAccCFAuthBackendConfigBasic(mount, params),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "identity_ca_certificates.#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "identity_ca_certificates.0", params.ca),
					resource.TestCheckResourceAttr(resourceAddress, "cf_api_addr", params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, "cf_username", params.username),
					resource.TestCheckResourceAttr(resourceAddress, "cf_password_wo_version", "1"),
				),
			},
			// Step 2: Update to full config with all optional fields.
			{
				Config: testAccCFAuthBackendConfigFull(mount, params),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "identity_ca_certificates.#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "cf_api_addr", params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, "cf_username", params.username),
					resource.TestCheckResourceAttr(resourceAddress, "cf_password_wo_version", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "cf_api_trusted_certificates.#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "cf_api_trusted_certificates.0", params.ca),
					resource.TestCheckResourceAttr(resourceAddress, "login_max_seconds_not_before", "60"),
					resource.TestCheckResourceAttr(resourceAddress, "login_max_seconds_not_after", "30"),
					resource.TestCheckResourceAttr(resourceAddress, "cf_timeout", "10"),
				),
			},
			// Step 3: Update write-only password by bumping cf_password_wo_version.
			{
				Config: testAccCFAuthBackendConfigUpdatePassword(mount, params),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "cf_username", params.username),
					resource.TestCheckResourceAttr(resourceAddress, "cf_password_wo_version", "2"),
					// Optional fields from the previous step should persist since
					// they are still in the config.
					resource.TestCheckResourceAttr(resourceAddress, "cf_api_trusted_certificates.#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "login_max_seconds_not_before", "60"),
					resource.TestCheckResourceAttr(resourceAddress, "login_max_seconds_not_after", "30"),
					resource.TestCheckResourceAttr(resourceAddress, "cf_timeout", "10"),
				),
			},
			// Step 4: Update optional fields only (login timing limits).
			{
				Config: testAccCFAuthBackendConfigUpdateOptional(mount, params),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "cf_api_addr", params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, "cf_username", params.username),
					resource.TestCheckResourceAttr(resourceAddress, "cf_password_wo_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "login_max_seconds_not_before", "120"),
					resource.TestCheckResourceAttr(resourceAddress, "login_max_seconds_not_after", "60"),
					resource.TestCheckResourceAttr(resourceAddress, "cf_timeout", "30"),
				),
			},
			// Step 5: Remove optional fields, revert to basic config.
			{
				Config: testAccCFAuthBackendConfigBasicV2(mount, params),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "cf_api_addr", params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, "cf_username", params.username),
					// Stay at version 2 so no spurious password update is triggered.
					resource.TestCheckResourceAttr(resourceAddress, "cf_password_wo_version", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "identity_ca_certificates.#", "1"),
					// Optional fields should be absent (cleared).
					resource.TestCheckNoResourceAttr(resourceAddress, "cf_api_trusted_certificates.#"),
				),
			},
			// Step 6: Import state. Write-only fields are excluded from verification.
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccCFAuthBackendConfigImportStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
				ImportStateVerifyIgnore:              []string{"cf_password_wo", "cf_password_wo_version"},
			},
			// Step 7: Destroy the config resource (keep the mount).
			{
				Config: testAccCFAuthBackendConfigMountOnly(mount),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectNonEmptyPlan(),
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionDestroy),
					},
				},
			},
		},
	})
}

func testAccCFAuthBackendConfigImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("auth/%s/config", rs.Primary.Attributes["mount"]), nil
	}
}

func testAccCFAuthBackendConfigMountOnly(mount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "cf" {
  type = "cf"
  path = "%s"
}
`, mount)
}

// testAccCFAuthBackendConfigBasic uses version=1.
func testAccCFAuthBackendConfigBasic(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 1
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.username, p.password)
}

// testAccCFAuthBackendConfigBasicV2 is the same as Basic but keeps version=2,
// used to revert to minimal config without triggering a spurious password update.
func testAccCFAuthBackendConfigBasicV2(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 2
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.username, p.password)
}

// testAccCFAuthBackendConfigFull adds all optional fields at version=1.
func testAccCFAuthBackendConfigFull(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                        = vault_auth_backend.cf.path
  identity_ca_certificates     = ["%s"]
  cf_api_addr                  = "%s"
  cf_username                  = "%s"
  cf_password_wo               = "%s"
  cf_password_wo_version       = 1
  cf_api_trusted_certificates  = ["%s"]
  login_max_seconds_not_before = 60
  login_max_seconds_not_after  = 30
  cf_timeout                   = 10
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.username, p.password, escapeHCL(p.ca))
}

// testAccCFAuthBackendConfigUpdatePassword bumps the write-only version to 2.
func testAccCFAuthBackendConfigUpdatePassword(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                        = vault_auth_backend.cf.path
  identity_ca_certificates     = ["%s"]
  cf_api_addr                  = "%s"
  cf_username                  = "%s"
  cf_password_wo               = "%s"
  cf_password_wo_version       = 2
  cf_api_trusted_certificates  = ["%s"]
  login_max_seconds_not_before = 60
  login_max_seconds_not_after  = 30
  cf_timeout                   = 10
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.username, p.password, escapeHCL(p.ca))
}

// testAccCFAuthBackendConfigUpdateOptional changes optional timing/timeout
// fields while keeping the same credentials (version stays at 2).
func testAccCFAuthBackendConfigUpdateOptional(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                        = vault_auth_backend.cf.path
  identity_ca_certificates     = ["%s"]
  cf_api_addr                  = "%s"
  cf_username                  = "%s"
  cf_password_wo               = "%s"
  cf_password_wo_version       = 2
  login_max_seconds_not_before = 120
  login_max_seconds_not_after  = 60
  cf_timeout                   = 30
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.username, p.password)
}

// escapeHCL escapes newlines in a PEM certificate for embedding in HCL strings.
func escapeHCL(s string) string {
	return strings.ReplaceAll(s, "\n", "\\n")
}
