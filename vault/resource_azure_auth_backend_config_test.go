// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAzureAuthBackendConfig_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("azure/foo/bar")

	resourceName := "vault_azure_auth_backend_config.config"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAzureAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				// Start with basic config
				Config: testAccAzureAuthBackendConfig_basic(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccAzureAuthBackendConfigCheck_attrs(backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "3"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "4"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "60"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldClientSecret},
			},
			{
				// Add max_retries
				Config: testAccAzureAuthBackendConfig_maxRetries(backend, 7),
				Check: resource.ComposeTestCheckFunc(
					testAccAzureAuthBackendConfigCheck_attrs(backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "7"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "4"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "60"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldClientSecret},
			},
			{
				// Add retry_delay
				Config: testAccAzureAuthBackendConfig_maxRetriesAndDelay(backend, 7, 8),
				Check: resource.ComposeTestCheckFunc(
					testAccAzureAuthBackendConfigCheck_attrs(backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "7"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "60"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldClientSecret},
			},
			{
				// Add max_retry_delay
				Config: testAccAzureAuthBackendConfig_retryFields(backend, 7, 8, 90),
				Check: resource.ComposeTestCheckFunc(
					testAccAzureAuthBackendConfigCheck_attrs(backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "7"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "90"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldClientSecret},
			},
		},
	})
}

func TestAccAzureAuthBackendConfig_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("azure")

	resourceType := "vault_azure_auth_backend_config"
	resourceName := resourceType + ".config"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckAzureAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAuthBackendConfig_basic(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccAzureAuthBackendConfigCheck_attrs(backend),
					// Check API defaults for retry fields
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "3"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "4"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "60"),
				),
			},
			{
				Config: testAccAzureAuthBackendConfig_updated(backend),
				Check:  testAccAzureAuthBackendConfigCheck_attrs(backend),
			},
			{
				// Add max_retries field
				Config: testAccAzureAuthBackendConfig_maxRetries(backend, 5),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "4"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "60"),
				),
			},
			{
				// Add retry_delay field
				Config: testAccAzureAuthBackendConfig_maxRetriesAndDelay(backend, 5, 10),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "60"),
				),
			},
			{
				// Add max_retry_delay field (all three fields now set)
				Config: testAccAzureAuthBackendConfig_retryFields(backend, 5, 10, 120),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "120"),
				),
			},
			{
				// Test updating all fields
				Config: testAccAzureAuthBackendConfig_retryFields(backend, 10, 5, 180),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "180"),
				),
			},
			{
				// Test with zero max_retries
				Config: testAccAzureAuthBackendConfig_retryFields(backend, 0, 1, 30),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetries, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRetryDelay, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryDelay, "30"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldClientSecret),
		},
	})
}

func TestAccAzureAuthBackend_wif(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-azure")
	updatedBackend := acctest.RandomWithPrefix("tf-test-azure-updated")

	resourceType := "vault_azure_auth_backend_config"
	resourceName := resourceType + ".config"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAuthBackendConfig_wifBasic(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "11111111-2222-3333-4444-222222222222"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "11111111-2222-3333-4444-333333333333"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldResource, "http://vault.hashicorp.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "600"),
				),
			},
			{
				Config: testAccAzureAuthBackendConfig_wifUpdated(updatedBackend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, updatedBackend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "22222222-3333-4444-5555-333333333333"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "22222222-3333-4444-5555-444444444444"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldResource, "http://vault.hashicorp.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "1800"),
				),
			},
		},
	})
}

func TestAccAzureAuthBackendConfig_automatedRotation(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-azure")

	resourceType := "vault_azure_auth_backend_config"
	resourceName := resourceType + ".config"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				// normal period setting
				Config: testAccAzureAuthBackendConfig_automatedRotation(backend, 600, "", 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				// switch to schedule
				Config: testAccAzureAuthBackendConfig_automatedRotation(backend, 0, "*/20 * * * SAT", 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * SAT"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				// disable it
				Config: testAccAzureAuthBackendConfig_automatedRotation(backend, 0, "", 0, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "true"),
				),
			},
			{
				// do an error
				Config:      testAccAzureAuthBackendConfig_automatedRotation(backend, 600, "", 900, false),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			{ // try again but with schedule (from nothing
				Config: testAccAzureAuthBackendConfig_automatedRotation(backend, 0, "*/20 * * * SUN", 3600, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * SUN"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldClientSecret),
		},
	})
}

func TestAccAzureAuthBackendConfig_ClientSecretWriteOnly(t *testing.T) {
	backend := acctest.RandomWithPrefix("azure")
	resourceName := "vault_azure_auth_backend_config.config"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAzureAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAuthBackendConfig_clientSecretWriteOnly(backend, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "test-tenant-id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "test-client-id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldResource, "https://management.azure.com/"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecretWOVersion, "1"),
					// Write-only field should not be in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientSecretWO),
					// Legacy field should not be set
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientSecret),
				),
			},
			{
				// Rotate secret by incrementing version
				Config: testAccAzureAuthBackendConfig_clientSecretWriteOnly(backend, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecretWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientSecretWO),
				),
			},
			{
				// Import should work with write-only fields
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldClientSecretWO, consts.FieldClientSecretWOVersion},
			},
		},
	})
}

func TestAccAzureAuthBackendConfig_ClientSecretLegacy(t *testing.T) {
	backend := acctest.RandomWithPrefix("azure")
	resourceName := "vault_azure_auth_backend_config.config"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAzureAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAuthBackendConfig_clientSecretLegacy(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, "test-client-secret"),
					// Write-only fields should not be set
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientSecretWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldClientSecretWOVersion),
				),
			},
		},
	})
}

func TestAccAzureAuthBackendConfig_ClientSecretWriteOnlyConflicts(t *testing.T) {
	backend := acctest.RandomWithPrefix("azure")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAzureAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				// Test ConflictsWith: client_secret and client_secret_wo cannot be used together
				Config:      testAccAzureAuthBackendConfig_clientSecretConflict(backend),
				ExpectError: regexp.MustCompile(`.*conflicts with.*`),
			},
			{
				// Test RequiredWith: client_secret_wo_version requires client_secret_wo
				Config:      testAccAzureAuthBackendConfig_versionWithoutClientSecretWO(backend),
				ExpectError: regexp.MustCompile(`all of\s+` + "`" + `client_secret_wo,client_secret_wo_version` + "`" + `\s+must be specified`),
			},
		},
	})
}

func testAccCheckAzureAuthBackendConfigDestroy(s *terraform.State) error {
	config := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_azure_auth_backend_config" {
			continue
		}
		secret, err := config.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for Azure auth backend %q config: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Azure auth backend %q still configured", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAzureAuthBackendConfig_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  type = "azure"
  path = "%s"
  description = "Test auth backend for Azure backend config"
}

resource "vault_azure_auth_backend_config" "config" {
  backend = vault_auth_backend.azure.path
  tenant_id = "11111111-2222-3333-4444-555555555555"
  client_id = "11111111-2222-3333-4444-555555555555"
  client_secret = "12345678901234567890"
  resource = "http://vault.hashicorp.com"
}
`, backend)
}

func testAccAzureAuthBackendConfigCheck_attrs(backend string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_azure_auth_backend_config.config"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := instanceState.ID

		if endpoint != "auth/"+backend+"/config" {
			return fmt.Errorf("expected ID to be %q, got %q", "auth/"+backend+"/config", endpoint)
		}

		config := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
		resp, err := config.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back Azure auth config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("Azure auth not configured at %q", endpoint)
		}
		attrs := map[string]string{
			consts.FieldTenantID:    consts.FieldTenantID,
			consts.FieldClientID:    consts.FieldClientID,
			consts.FieldResource:    consts.FieldResource,
			consts.FieldEnvironment: consts.FieldEnvironment,
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			if resp.Data[apiAttr] != instanceState.Attributes[stateAttr] {
				return fmt.Errorf("expected %s (%s) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
}

func testAccAzureAuthBackendConfig_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
  description = "Test auth backend for Azure backend config"
}

resource "vault_azure_auth_backend_config" "config" {
  backend = vault_auth_backend.azure.path
  tenant_id = "11111111-2222-3333-4444-555555555555"
  client_id = "11111111-2222-3333-4444-555555555555"
  client_secret = "12345678901234567890"
  resource = "http://vault.hashicorp.com"
}`, backend)
}

func testAccAzureAuthBackendConfig_wifBasic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend                 = vault_auth_backend.azure.path
  tenant_id               = "11111111-2222-3333-4444-222222222222"
  client_id               = "11111111-2222-3333-4444-333333333333"
  resource                = "http://vault.hashicorp.com"
  identity_token_audience = "wif-audience"
  identity_token_ttl      = 600
}`, backend)
}

func testAccAzureAuthBackendConfig_wifUpdated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend                 = vault_auth_backend.azure.path
  tenant_id               = "22222222-3333-4444-5555-333333333333"
  client_id               = "22222222-3333-4444-5555-444444444444"
  resource                = "http://vault.hashicorp.com"
  identity_token_audience = "wif-audience-updated"
  identity_token_ttl 	  = 1800
}`, backend)
}

func testAccAzureAuthBackendConfig_retryFields(backend string, maxRetries int, retryDelay int, maxRetryDelay int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend = vault_auth_backend.azure.path
  tenant_id = "11111111-2222-3333-4444-555555555555"
  client_id = "11111111-2222-3333-4444-555555555555"
  client_secret = "12345678901234567890"
  resource = "http://vault.hashicorp.com"
  max_retries = %d
  retry_delay = %d
  max_retry_delay = %d
}`, backend, maxRetries, retryDelay, maxRetryDelay)
}

func testAccAzureAuthBackendConfig_maxRetries(backend string, maxRetries int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend = vault_auth_backend.azure.path
  tenant_id = "11111111-2222-3333-4444-555555555555"
  client_id = "11111111-2222-3333-4444-555555555555"
  client_secret = "12345678901234567890"
  resource = "http://vault.hashicorp.com"
  max_retries = %d
}`, backend, maxRetries)
}

func testAccAzureAuthBackendConfig_maxRetriesAndDelay(backend string, maxRetries int, retryDelay int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend = vault_auth_backend.azure.path
  tenant_id = "11111111-2222-3333-4444-555555555555"
  client_id = "11111111-2222-3333-4444-555555555555"
  client_secret = "12345678901234567890"
  resource = "http://vault.hashicorp.com"
  max_retries = %d
  retry_delay = %d
}`, backend, maxRetries, retryDelay)
}

func testAccAzureAuthBackendConfig_automatedRotation(backend string, periodDuration int, scheduleString string, windowDuration int, disableRotation bool) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend = vault_auth_backend.azure.path
  tenant_id = "11111111-2222-3333-4444-555555555555"
  client_id = "11111111-2222-3333-4444-555555555555"
  client_secret = "12345678901234567890"
  resource = "http://vault.hashicorp.com"
  rotation_period = "%d"
  rotation_schedule = "%s"
  rotation_window = "%d"
  disable_automated_rotation = %t
}`, backend, periodDuration, scheduleString, windowDuration, disableRotation)
}

func testAccAzureAuthBackendConfig_clientSecretWriteOnly(backend string, version int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend                   = vault_auth_backend.azure.path
  tenant_id                 = "test-tenant-id"
  client_id                 = "test-client-id"
  client_secret_wo          = "test-client-secret-wo-%d"
  client_secret_wo_version  = %d
  resource                  = "https://management.azure.com/"
}
`, backend, version, version)
}

func testAccAzureAuthBackendConfig_clientSecretLegacy(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend       = vault_auth_backend.azure.path
  tenant_id     = "test-tenant-id"
  client_id     = "test-client-id"
  client_secret = "test-client-secret"
  resource      = "https://management.azure.com/"
}
`, backend)
}

func testAccAzureAuthBackendConfig_clientSecretConflict(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend                   = vault_auth_backend.azure.path
  tenant_id                 = "test-tenant-id"
  client_id                 = "test-client-id"
  client_secret             = "legacy-secret"
  client_secret_wo          = "write-only-secret"
  client_secret_wo_version  = 1
  resource                  = "https://management.azure.com/"
}
`, backend)
}

func testAccAzureAuthBackendConfig_versionWithoutClientSecretWO(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_azure_auth_backend_config" "config" {
  backend                   = vault_auth_backend.azure.path
  tenant_id                 = "test-tenant-id"
  client_id                 = "test-client-id"
  client_secret             = "legacy-secret"
  client_secret_wo_version  = 1
  resource                  = "https://management.azure.com/"
}
`, backend)
}

func testAccAzureAuthBackend_destroyed(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}
`, backend)
}
