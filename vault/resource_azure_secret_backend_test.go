// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

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
		ProviderFactories: providerFactories,
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
			// Clear out previous test step that uses use_microsoft_graph_api
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
	}

	if !isUpdate {
		baseChecks = append(baseChecks, commonInitialChecks...)
	} else {
		baseChecks = append(baseChecks, commonUpdateChecks...)
	}

	return func(state *terraform.State) error {
		var checks []resource.TestCheckFunc
		meta := testProvider.Meta().(*provider.ProviderMeta)
		var extras []resource.TestCheckFunc
		// only check use_microsoft_graph_api if Vault version is
		// < 1.12.0
		if !meta.IsAPISupported(provider.VaultVersion112) {
			if !isUpdate {
				extras = []resource.TestCheckFunc{
					resource.TestCheckResourceAttr(resourceName, consts.FieldUseMSGraphAPI, "false"),
				}
			} else {
				extras = []resource.TestCheckFunc{
					resource.TestCheckResourceAttr(resourceName, consts.FieldUseMSGraphAPI, "true"),
				}
			}
			checks = append(baseChecks, extras...)
		} else {
			checks = baseChecks
		}
		return resource.ComposeAggregateTestCheckFunc(checks...)(state)
	}
}

func TestAccAzureSecretBackend_wif(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-azure")
	updatedPath := acctest.RandomWithPrefix("tf-test-azure-updated")

	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
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
		ProviderFactories: providerFactories,
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
		ProviderFactories: providerFactories,
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
  use_microsoft_graph_api = true
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
}`, path)
	}
}
