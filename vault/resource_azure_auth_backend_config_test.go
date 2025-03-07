// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAzureAuthBackendConfig_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("azure/foo/bar")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckAzureAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAuthBackendConfig_basic(backend),
				Check:  testAccAzureAuthBackendConfigCheck_attrs(backend),
			},
			{
				ResourceName:            "vault_azure_auth_backend_config.config",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldClientSecret},
			},
		},
	})
}

func TestAccAzureAuthBackendConfig_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("azure")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccCheckAzureAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAuthBackendConfig_basic(backend),
				Check:  testAccAzureAuthBackendConfigCheck_attrs(backend),
			},
			{
				Config: testAccAzureAuthBackendConfig_updated(backend),
				Check:  testAccAzureAuthBackendConfigCheck_attrs(backend),
			},
		},
	})
}

func TestAccAzureAuthBackend_wif(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-azure")
	updatedBackend := acctest.RandomWithPrefix("tf-test-azure-updated")

	resourceType := "vault_azure_auth_backend_config"
	resourceName := resourceType + ".config"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
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
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				// normal period setting
				Config: testAccAzureAuthBackendConfig_automatedRotation(backend, "10m", "", "", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "10m"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				// switch to schedule
				Config: testAccAzureAuthBackendConfig_automatedRotation(backend, "", "*/20 * * * SAT", "", false),
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
				Config: testAccAzureAuthBackendConfig_automatedRotation(backend, "", "", "", true),
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
				Config:      testAccAzureAuthBackendConfig_automatedRotation(backend, "10m", "", "15m", false),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldClientSecret),
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

func testAccAzureAuthBackendConfig_automatedRotation(backend, periodDuration, scheduleString, windowDuration string, disableRotation bool) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
}

resource "vault_auth_azure_backend_config" "config" {
  backend = vault_auth_backend.azure.path
  tenant_id = "11111111-2222-3333-4444-555555555555"
  client_id = "11111111-2222-3333-4444-555555555555"
  client_secret = "12345678901234567890"
  resource = "http://vault.hashicorp.com"
  rotation_period = "%s"
  rotation_schedule = "%s"
  rotation_window = "%s"
  disable_automated_rotation = %t
}`, backend, periodDuration, scheduleString, windowDuration, disableRotation)
}
