// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudfoundry_test

import (
	"fmt"
	"os"
	"regexp"
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
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldIdentityCACertificates+".#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldIdentityCACertificates+".0", params.ca),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFApiAddr, params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFUsername, params.username),
					// Write-only field must never be stored in state.
					resource.TestCheckNoResourceAttr(resourceAddress, consts.FieldCFPasswordWO),
					// Version field should be stored in state
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFPasswordWOVersion, "1"),
					// Computed fields must be populated with Vault's defaults even when
					// not explicitly set in config.
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotBefore, "300"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotAfter, "60"),
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
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldIdentityCACertificates+".#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFApiAddr, params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFUsername, params.username),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFApiTrustedCertificates+".#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFApiTrustedCertificates+".0", params.ca),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotBefore, "60"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotAfter, "30"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFTimeout, "10"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Re-apply the full config to assert idempotency with the
			// write-only required attribute (cf_password_wo). Because the field is
			// write-only, Vault never returns it; the provider must not produce a
			// diff when the same password value is supplied again.
			{
				Config: testAccCFAuthBackendConfigIdempotentPassword(mount, params),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFUsername, params.username),
					// Optional fields from the previous step should persist since
					// they are still in the config.
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFApiTrustedCertificates+".#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotBefore, "60"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotAfter, "30"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFTimeout, "10"),
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
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFApiAddr, params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFUsername, params.username),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotBefore, "120"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotAfter, "60"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFTimeout, "30"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 5: Remove optional fields, revert to basic config.
			// cf_api_trusted_certificates is cleared because Vault accepts an empty
			// list as an explicit reset.
			// login_max_seconds_not_before/after are Optional+Computed: Vault treats
			// the zero value sent as "keep existing", so their Step-4 values are
			// retained; Terraform accepts this because the fields are Computed.
			// cf_timeout is Optional-only: its zero value means "no timeout" in
			// Vault, which resets the field, and the read path maps 0 → null.
			{
				Config: testAccCFAuthBackendConfigBasic(mount, params),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFApiAddr, params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFUsername, params.username),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldIdentityCACertificates+".#", "1"),
					// cf_api_trusted_certificates is explicitly cleared (empty list sent).
					resource.TestCheckNoResourceAttr(resourceAddress, consts.FieldCFApiTrustedCertificates+".#"),
					// login_max_seconds_not_before/after are Computed: Vault retains the
					// previously set values (120/60) because it treats 0 as "no change".
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotBefore, "120"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldLoginMaxSecsNotAfter, "60"),
					// cf_timeout defaults to 0 (no timeout); Vault resets it when 0 is
					// sent, so removing it from config clears it from state.
					resource.TestCheckNoResourceAttr(resourceAddress, consts.FieldCFTimeout),
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
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldCFPasswordWO, consts.FieldCFPasswordWOVersion},
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
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the config inside a namespace.
			{
				Config: testAccCFAuthBackendConfigNamespace(ns, mount, params),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFApiAddr, params.apiAddr),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFUsername, params.username),
					resource.TestCheckNoResourceAttr(resourceAddress, consts.FieldCFPasswordWO),
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
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldIdentityCACertificates+".#", "2"),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFApiTrustedCertificates+".#", "2"),
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

// TestAccCFAuthBackendConfigInvalid combines all negative-path test cases into
// a single test to keep invalid-input coverage together. Each step supplies a
// deliberately broken config and asserts that Terraform (or Vault) rejects it
// with an error.
func TestAccCFAuthBackendConfigInvalid(t *testing.T) {
	mount := acctest.RandomWithPrefix("cf-mount")

	params := cfTestParamsFromEnv(t)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Invalid cf_api_addr: not a valid URL, Vault rejects the config write.
			{
				Config:      testAccCFAuthBackendConfigInvalidAPIAddr(mount, params),
				ExpectError: regexp.MustCompile(`(?i)(invalid|error|failed|not valid)`),
			},
			// Missing cf_username: required field omitted; provider/Vault rejects.
			{
				Config:      testAccCFAuthBackendConfigMissingUsername(mount, params),
				ExpectError: regexp.MustCompile(`(?i)(required|missing|error)`),
			},
			// Missing cf_password_wo: required field omitted; provider rejects.
			{
				Config:      testAccCFAuthBackendConfigMissingPassword(mount, params),
				ExpectError: regexp.MustCompile(`(?i)(required|missing|error)`),
			},
			// Missing cf_api_addr: required field omitted; provider rejects.
			{
				Config:      testAccCFAuthBackendConfigMissingAPIAddr(mount, params),
				ExpectError: regexp.MustCompile(`(?i)(required|missing|error)`),
			},
			// Invalid namespace: namespace does not exist in Vault.
			{
				Config:      testAccCFAuthBackendConfigInvalidNamespace(mount, params),
				ExpectError: regexp.MustCompile(`(?i)(namespace|not found|error)`),
			},
		},
	})
}

// TestAccCFAuthBackendConfigPasswordVersionTracking tests that the cf_password_wo_version
// field correctly triggers password updates when incremented.
func TestAccCFAuthBackendConfigPasswordVersionTracking(t *testing.T) {
	mount := acctest.RandomWithPrefix("cf-mount")
	resourceAddress := "vault_cf_auth_backend_config.test"

	params := cfTestParamsFromEnv(t)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with write-only password (version 1)
			{
				Config: testAccCFAuthBackendConfigPasswordVersion(mount, params, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFPasswordWOVersion, "1"),
					resource.TestCheckNoResourceAttr(resourceAddress, consts.FieldCFPasswordWO),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Update password by incrementing version to 2
			{
				Config: testAccCFAuthBackendConfigPasswordVersion(mount, params, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFPasswordWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceAddress, consts.FieldCFPasswordWO),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Keep version at 2 - should not trigger password update
			{
				Config: testAccCFAuthBackendConfigPasswordVersion(mount, params, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldCFPasswordWOVersion, "2"),
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

func testAccCFAuthBackendConfigInvalidAPIAddr(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "not-a-valid-url"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 1
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.username, p.password)
}

func testAccCFAuthBackendConfigMissingUsername(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 1
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.password)
}

func testAccCFAuthBackendConfigMissingPassword(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.username)
}

func testAccCFAuthBackendConfigMissingAPIAddr(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 1
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.username, p.password)
}

func testAccCFAuthBackendConfigInvalidNamespace(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  namespace                = "nonexistent-namespace"
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 1
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.username, p.password)
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

// testAccCFAuthBackendConfigBasic creates a config with only the required fields.
func testAccCFAuthBackendConfigBasic(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version       = 1

}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.username, p.password)
}

// testAccCFAuthBackendConfigFull creates a config with all optional fields set.
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

// testAccCFAuthBackendConfigIdempotentPassword re-applies the same full config
// (including the write-only cf_password_wo) to assert that the provider does
// not produce a spurious diff when a write-only required attribute is unchanged.
func testAccCFAuthBackendConfigIdempotentPassword(mount string, p cfTestParams) string {
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

// testAccCFAuthBackendConfigUpdateOptional changes optional timing/timeout
// fields while keeping the same credentials.
func testAccCFAuthBackendConfigUpdateOptional(mount string, p cfTestParams) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                        = vault_auth_backend.cf.path
  identity_ca_certificates     = ["%s"]
  cf_api_addr                  = "%s"
  cf_username                  = "%s"
  cf_password_wo               = "%s"
  cf_password_wo_version       = 1
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

// testAccCFAuthBackendConfigPasswordVersion creates a config with a specific password version
func testAccCFAuthBackendConfigPasswordVersion(mount string, p cfTestParams, version int) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = %d
}
`, testAccCFAuthBackendConfigMountOnly(mount), escapeHCL(p.ca), p.apiAddr, p.username, p.password, version)
}
