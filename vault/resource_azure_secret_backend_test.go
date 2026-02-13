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

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAzureSecretBackend(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-azure")
	updatedPath := acctest.RandomWithPrefix("tf-test-azure-updated")
	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretBackend_initialConfig(path),
				Check:  getAzureBackendChecks(resourceName, path, false),
			},
			{
				Config: testAzureSecretBackend_updated(path),
				Check:  getAzureBackendChecks(resourceName, path, true),
			},
			// Clear out previous test step
			// allows for a cleaner import test
			{
				Config: testAzureSecretBackend_initialConfig(updatedPath),
				Check:  getAzureBackendChecks(resourceName, updatedPath, false),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldClientSecret, consts.FieldDisableRemount),
		},
	})
}

func getAzureBackendChecks(resourceName, path string, isUpdate bool) resource.TestCheckFunc {
	baseChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
	}

	commonInitialChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "11111111-2222-3333-4444-222222222222"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "11111111-2222-3333-4444-333333333333"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, "12345678901234567890"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldEnvironment, "AzurePublicCloud"),
	}

	commonUpdateChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "22222222-3333-4444-5555-333333333333"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "22222222-3333-4444-5555-444444444444"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, "098765432109876543214"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldEnvironment, "AzurePublicCloud"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldRootPasswordTTL, "2000000"),
	}

	if !isUpdate {
		baseChecks = append(baseChecks, commonInitialChecks...)
	} else {
		baseChecks = append(baseChecks, commonUpdateChecks...)
	}

	return func(state *terraform.State) error {
		return resource.ComposeAggregateTestCheckFunc(baseChecks...)(state)
	}
}

func TestAccAzureSecretBackend_wif(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-azure")
	updatedPath := acctest.RandomWithPrefix("tf-test-azure-updated")

	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAzureSecretBackendConfig_wifBasic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "11111111-2222-3333-4444-222222222222"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "11111111-2222-3333-4444-333333333333"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "600"),
				),
			},
			{
				Config: testAccAzureSecretBackendConfig_wifUpdated(updatedPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "22222222-3333-4444-5555-333333333333"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "22222222-3333-4444-5555-444444444444"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "wif-audience-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "1800"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDisableRemount),
		},
	})
}

func TestAccAzureSecretBackend_MountConfig(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-azure")

	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAzureSecretBackendConfig_MountConfig(path, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "22222222-3333-4444-5555-333333333333"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "22222222-3333-4444-5555-444444444444"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test desc"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "36000"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.0", "header1"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.0", "header1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resourceName, "force_no_cache", "true"),
				),
			},
			{
				Config: testAccAzureSecretBackendConfig_MountConfig(path, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "22222222-3333-4444-5555-333333333333"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "22222222-3333-4444-5555-444444444444"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test desc updated"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "48000"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.0", "header1"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.0", "header1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.1", "header2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.2", "header3"),
					resource.TestCheckResourceAttr(resourceName, "listing_visibility", "unauth"),
					resource.TestCheckResourceAttr(resourceName, "force_no_cache", "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldDisableRemount,
				consts.FieldClientSecret),
		},
	})
}

func TestAzureSecretBackend_remount(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-azure")
	updatedPath := acctest.RandomWithPrefix("tf-test-azure-updated")

	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"
	azureInitialCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "11111111-2222-3333-4444-222222222222"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "11111111-2222-3333-4444-333333333333"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, "12345678901234567890"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldEnvironment, "AzurePublicCloud"),
	}

	azureUpdatedCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
		resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "11111111-2222-3333-4444-222222222222"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "11111111-2222-3333-4444-333333333333"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, "12345678901234567890"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldEnvironment, "AzurePublicCloud"),
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretBackend_remount(path),
				Check:  resource.ComposeTestCheckFunc(azureInitialCheckFuncs...),
			},
			{
				Config: testAzureSecretBackend_remount(updatedPath),
				Check:  resource.ComposeTestCheckFunc(azureUpdatedCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldClientSecret, consts.FieldDisableRemount),
		},
	})
}

func TestAccAzureSecretBackendConfig_automatedRotation(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-azure")

	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				// normal period setting
				Config: testAccAzureSecretBackendConfig_automatedRotation(backend, "", 0, 600, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				// switch to schedule
				Config: testAccAzureSecretBackendConfig_automatedRotation(backend, "*/20 * * * SAT", 0, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * SAT"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				// disable it
				Config: testAccAzureSecretBackendConfig_automatedRotation(backend, "", 0, 0, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "true"),
				),
			},
			{
				// do an error
				Config:      testAccAzureSecretBackendConfig_automatedRotation(backend, "", 900, 600, false),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			{ // try again but with schedule (from nothing
				Config: testAccAzureSecretBackendConfig_automatedRotation(backend, "*/20 * * * SUN", 3600, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * SUN"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldClientSecret, consts.FieldDisableRemount),
		},
	})
}

func testAzureSecretBackend_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path            = "%s"
  subscription_id = "11111111-2222-3333-4444-111111111111"
  tenant_id       = "11111111-2222-3333-4444-222222222222"
  client_id       = "11111111-2222-3333-4444-333333333333"
  client_secret   = "12345678901234567890"
  environment     = "AzurePublicCloud"
  disable_remount = true
}`, path)
}

func testAzureSecretBackend_updated(path string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path                    = "%s"
  subscription_id         = "11111111-2222-3333-4444-111111111111"
  tenant_id               = "22222222-3333-4444-5555-333333333333"
  client_id               = "22222222-3333-4444-5555-444444444444"
  client_secret           = "098765432109876543214"
  environment             = "AzurePublicCloud"
  disable_remount         = true
  root_password_ttl 	  = 2000000
}`, path)
}

func testAzureSecretBackend_remount(path string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path            = "%s"
  subscription_id = "11111111-2222-3333-4444-111111111111"
  tenant_id       = "11111111-2222-3333-4444-222222222222"
  client_id       = "11111111-2222-3333-4444-333333333333"
  client_secret   = "12345678901234567890"
  environment     = "AzurePublicCloud"
}`, path)
}

func testAccAzureSecretBackendConfig_wifBasic(path string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path 					  = "%s"
  subscription_id 		  = "11111111-2222-3333-4444-111111111111"
  tenant_id       		  = "11111111-2222-3333-4444-222222222222"
  client_id       		  = "11111111-2222-3333-4444-333333333333"
  identity_token_audience = "wif-audience"
  identity_token_ttl 	  = 600
}`, path)
}

func testAccAzureSecretBackendConfig_wifUpdated(path string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path 					  = "%s"
  subscription_id         = "11111111-2222-3333-4444-111111111111"
  tenant_id               = "22222222-3333-4444-5555-333333333333"
  client_id               = "22222222-3333-4444-5555-444444444444"
  identity_token_audience = "wif-audience-updated"
  identity_token_ttl 	  = 1800
}`, path)
}

func testAccAzureSecretBackendConfig_MountConfig(path string, isUpdate bool) string {

	if !isUpdate {
		return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path 					      = "%s"
  description 			      = "test desc"
  subscription_id             = "11111111-2222-3333-4444-111111111111"
  tenant_id                   = "22222222-3333-4444-5555-333333333333"
  client_id                   = "22222222-3333-4444-5555-444444444444"
  client_secret               = "12345678901234567890"
  default_lease_ttl_seconds   = 3600
  max_lease_ttl_seconds       = 36000
  passthrough_request_headers = ["header1", "header2"]
  allowed_response_headers    = ["header1", "header2"]
  delegated_auth_accessors    = ["header1", "header2"]
  listing_visibility          = "hidden"
  force_no_cache              = true
}`, path)
	} else {
		return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path 					      = "%s"
  description 			      = "test desc updated"
  subscription_id             = "11111111-2222-3333-4444-111111111111"
  tenant_id                   = "22222222-3333-4444-5555-333333333333"
  client_id                   = "22222222-3333-4444-5555-444444444444"
  client_secret               = "12345678901234567890"
  default_lease_ttl_seconds   = 7200
  max_lease_ttl_seconds       = 48000
  passthrough_request_headers = ["header1", "header2"]
  allowed_response_headers    = ["header1", "header2", "header3"]
  delegated_auth_accessors    = ["header1", "header2"]
  listing_visibility          = "unauth"
  force_no_cache              = true
}`, path)
	}
}

func testAccAzureSecretBackendConfig_automatedRotation(path string, rotationSchedule string, rotationWindow, rotationPeriod int, disableRotation bool) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path 					  = "%s"
  subscription_id         = "11111111-2222-3333-4444-111111111111"
  tenant_id               = "22222222-3333-4444-5555-333333333333"
  client_id               = "22222222-3333-4444-5555-444444444444"
  rotation_schedule       = "%s"
  rotation_window         = "%d"
  rotation_period         = "%d"
  disable_automated_rotation = %t
}
`, path, rotationSchedule, rotationWindow, rotationPeriod, disableRotation)
}

func TestAccAzureSecretBackend_clientSecretWriteOnly(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-azure")
	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccAzureSecretBackendConfig_clientSecretWO(path, "12345678901234567890", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "11111111-2222-3333-4444-222222222222"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "11111111-2222-3333-4444-333333333333"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecretWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnvironment, "AzurePublicCloud"),
				),
			},
			{
				Config: testAccAzureSecretBackendConfig_clientSecretWO(path, "098765432109876543214", 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecretWOVersion, "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldClientSecretWO, consts.FieldClientSecretWOVersion, consts.FieldDisableRemount),
		},
	})
}

func testAccAzureSecretBackendConfig_clientSecretWO(path, clientSecret string, version int) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path                     = "%s"
  subscription_id          = "11111111-2222-3333-4444-111111111111"
  tenant_id                = "11111111-2222-3333-4444-222222222222"
  client_id                = "11111111-2222-3333-4444-333333333333"
  client_secret_wo         = "%s"
  client_secret_wo_version = %d
  environment              = "AzurePublicCloud"
  disable_remount          = true
}`, path, clientSecret, version)
}

func TestAccAzureSecretBackend_clientSecretConflicts(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-azure")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  path                     = "%s"
  subscription_id          = "11111111-2222-3333-4444-111111111111"
  tenant_id                = "11111111-2222-3333-4444-222222222222"
  client_id                = "11111111-2222-3333-4444-333333333333"
  client_secret            = "test-client-secret"
  client_secret_wo         = "test-client-secret-wo"
  client_secret_wo_version = 1
}`, path),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
		},
	})
}
