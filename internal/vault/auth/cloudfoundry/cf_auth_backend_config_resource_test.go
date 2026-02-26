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
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
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
// When CF_TEST_API_ADDR is unset the test is skipped, because Vault's CF auth
// plugin contacts the CF API when writing the config and there is no real
// endpoint to reach.
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
		t.Skip("CF_TEST_API_ADDR not set: skipping test that requires a reachable CF API")
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
			acctestutil.TestAccPreCheck(t)
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
					// Write-only field must never be stored in state.
					resource.TestCheckNoResourceAttr(resourceAddress, "cf_password_wo"),
				),
				// Idempotency: re-applying the same config must produce no diff.
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
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
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
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
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
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
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
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
					// All optional fields must be cleared after reverting to basic config.
					resource.TestCheckNoResourceAttr(resourceAddress, "cf_api_trusted_certificates.#"),
					resource.TestCheckNoResourceAttr(resourceAddress, "login_max_seconds_not_before"),
					resource.TestCheckNoResourceAttr(resourceAddress, "login_max_seconds_not_after"),
					resource.TestCheckNoResourceAttr(resourceAddress, "cf_timeout"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
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

// TestAccCFAuthBackendConfigNamespace verifies that the resource works correctly
// when deployed inside a Vault namespace (Enterprise only).
func TestAccCFAuthBackendConfigNamespace(t *testing.T) {
	mount := acctest.RandomWithPrefix("cf-mount")
	ns := acctest.RandomWithPrefix("ns")
	resourceAddress := "vault_cf_auth_backend_config.test"

	params := cfTestParamsFromEnv(t)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the config inside a namespace.
			{
				Config: testAccCFAuthBackendConfigNamespace(ns, mount, params),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "cf_api_addr", params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, "cf_username", params.username),
					resource.TestCheckNoResourceAttr(resourceAddress, "cf_password_wo"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccCFAuthBackendConfigMultipleCerts verifies that identity_ca_certificates
// and cf_api_trusted_certificates accept multiple entries and round-trip correctly.
func TestAccCFAuthBackendConfigMultipleCerts(t *testing.T) {
	mount := acctest.RandomWithPrefix("cf-mount")
	resourceAddress := "vault_cf_auth_backend_config.test"

	params := cfTestParamsFromEnv(t)

	// Generate a second CA certificate to populate list fields with >1 element.
	caBytes2, _, err := testutil.GenerateCA()
	if err != nil {
		t.Fatalf("failed to generate second CA cert: %s", err)
	}
	ca2 := strings.TrimSpace(string(caBytes2))

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create config with two identity_ca_certificates and two
			// cf_api_trusted_certificates to exercise list handling.
			{
				Config: testAccCFAuthBackendConfigMultipleCerts(mount, params, ca2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "identity_ca_certificates.#", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "cf_api_trusted_certificates.#", "2"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
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

// testAccCFAuthBackendConfigNamespace creates a vault_namespace and deploys the
// CF auth backend config inside it to verify namespace-scoped operation.
func testAccCFAuthBackendConfigNamespace(ns, mount string, p cfTestParams) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_auth_backend" "cf" {
  type      = "cf"
  path      = "%s"
  namespace = vault_namespace.test.path
}

resource "vault_cf_auth_backend_config" "test" {
  namespace                = vault_namespace.test.path
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 1
}
`, ns, mount, escapeHCL(p.ca), p.apiAddr, p.username, p.password)
}

// testAccCFAuthBackendConfigMultipleCerts creates a config with two entries in
// each list field to verify multi-element list round-tripping.
func testAccCFAuthBackendConfigMultipleCerts(mount string, p cfTestParams, ca2 string) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                       = vault_auth_backend.cf.path
  identity_ca_certificates    = ["%s", "%s"]
  cf_api_addr                 = "%s"
  cf_username                 = "%s"
  cf_password_wo              = "%s"
  cf_password_wo_version      = 1
  cf_api_trusted_certificates = ["%s", "%s"]
}
`, testAccCFAuthBackendConfigMountOnly(mount),
		escapeHCL(p.ca), escapeHCL(ca2),
		p.apiAddr, p.username, p.password,
		escapeHCL(p.ca), escapeHCL(ca2))
}

// escapeHCL escapes newlines in a PEM certificate for embedding in HCL strings.
func escapeHCL(s string) string {
	return strings.ReplaceAll(s, "\n", "\\n")
}
