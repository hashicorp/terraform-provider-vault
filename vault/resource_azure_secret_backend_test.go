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
				"client_secret", "disable_remount"),
		},
	})
}

func getAzureBackendChecks(resourceName, path string, isUpdate bool) resource.TestCheckFunc {
	baseChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
	}

	commonInitialChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, "tenant_id", "11111111-2222-3333-4444-222222222222"),
		resource.TestCheckResourceAttr(resourceName, "client_id", "11111111-2222-3333-4444-333333333333"),
		resource.TestCheckResourceAttr(resourceName, "client_secret", "12345678901234567890"),
		resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
	}

	commonUpdateChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, "tenant_id", "22222222-3333-4444-5555-333333333333"),
		resource.TestCheckResourceAttr(resourceName, "client_id", "22222222-3333-4444-5555-444444444444"),
		resource.TestCheckResourceAttr(resourceName, "client_secret", "098765432109876543214"),
		resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
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
					resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "false"),
				}
			} else {
				extras = []resource.TestCheckFunc{
					resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "true"),
				}
			}
			checks = append(baseChecks, extras...)
		} else {
			checks = baseChecks
		}
		return resource.ComposeAggregateTestCheckFunc(checks...)(state)
	}
}

func TestAzureSecretBackend_remount(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-azure")
	updatedPath := acctest.RandomWithPrefix("tf-test-azure-updated")

	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"
	azureInitialCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
		resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, "tenant_id", "11111111-2222-3333-4444-222222222222"),
		resource.TestCheckResourceAttr(resourceName, "client_id", "11111111-2222-3333-4444-333333333333"),
		resource.TestCheckResourceAttr(resourceName, "client_secret", "12345678901234567890"),
		resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
	}

	azureUpdatedCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
		resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, "tenant_id", "11111111-2222-3333-4444-222222222222"),
		resource.TestCheckResourceAttr(resourceName, "client_id", "11111111-2222-3333-4444-333333333333"),
		resource.TestCheckResourceAttr(resourceName, "client_secret", "12345678901234567890"),
		resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
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
			testutil.GetImportTestStep(resourceName, false, nil, "client_secret", "disable_remount"),
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
