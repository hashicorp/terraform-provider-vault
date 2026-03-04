// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtAzureKMS(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_KEYVAULT_NAME")

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("azurekms")
	resourceType := "vault_keymgmt_azure_kms"
	resourceName := resourceType + ".test"

	keyVaultName := os.Getenv("AZURE_KEYVAULT_NAME")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAzureKMSConfig(mount, kmsName, keyVaultName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", keyVaultName),
					resource.TestCheckResourceAttr(resourceName, "tenant_id", os.Getenv("AZURE_TENANT_ID")),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtAzureKMSImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore: []string{
					"client_id",
					"client_secret",
					"environment",
					"tenant_id",
				},
			},
		},
	})
}

func TestAccKeymgmtAzureKMS_update(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_KEYVAULT_NAME")

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("azurekms")
	resourceType := "vault_keymgmt_azure_kms"
	resourceName := resourceType + ".test"

	keyVaultName := os.Getenv("AZURE_KEYVAULT_NAME")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAzureKMSConfig(mount, kmsName, keyVaultName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", keyVaultName),
					resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
				),
			},
			{
				Config: testKeymgmtAzureKMSConfigWithEnvironment(mount, kmsName, keyVaultName, "AzureUSGovernmentCloud"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "environment", "AzureUSGovernmentCloud"),
				),
			},
		},
	})
}

func TestAccKeymgmtAzureKMS_environments(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_KEYVAULT_NAME")

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyVaultName := os.Getenv("AZURE_KEYVAULT_NAME")

	environments := []struct {
		name string
		env  string
	}{
		{"public", "AzurePublicCloud"},
		{"usgovt", "AzureUSGovernmentCloud"},
		{"german", "AzureGermanCloud"},
		{"china", "AzureChinaCloud"},
	}

	for _, tc := range environments {
		t.Run(tc.name, func(t *testing.T) {
			kmsName := acctest.RandomWithPrefix("azurekms-" + tc.name)
			resourceName := "vault_keymgmt_azure_kms.test"

			resource.Test(t, resource.TestCase{
				ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
				PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config: testKeymgmtAzureKMSConfigWithEnvironment(mount, kmsName, keyVaultName, tc.env),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
							resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
							resource.TestCheckResourceAttr(resourceName, "environment", tc.env),
						),
					},
				},
			})
		})
	}
}

func TestAccKeymgmtAzureKMS_multiple(t *testing.T) {
	testutil.SkipTestEnvUnset(t, "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_KEYVAULT_NAME")

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName1 := acctest.RandomWithPrefix("azurekms-1")
	kmsName2 := acctest.RandomWithPrefix("azurekms-2")
	keyVaultName := os.Getenv("AZURE_KEYVAULT_NAME")
	resourceName1 := "vault_keymgmt_azure_kms.test1"
	resourceName2 := "vault_keymgmt_azure_kms.test2"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAzureKMSConfigMultiple(mount, kmsName1, kmsName2, keyVaultName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldName, kmsName1),
					resource.TestCheckResourceAttr(resourceName1, "key_collection", keyVaultName),
					resource.TestCheckResourceAttr(resourceName1, "environment", "AzurePublicCloud"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldName, kmsName2),
					resource.TestCheckResourceAttr(resourceName2, "key_collection", keyVaultName),
					resource.TestCheckResourceAttr(resourceName2, "environment", "AzureUSGovernmentCloud"),
				),
			},
		},
	})
}

func testAccKeymgmtAzureKMSImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		path := rs.Primary.Attributes[consts.FieldPath]
		name := rs.Primary.Attributes[consts.FieldName]
		return fmt.Sprintf("%s/kms/%s", path, name), nil
	}
}

func testKeymgmtAzureKMSConfig(mount, kmsName, keyVaultName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_azure_kms" "test" {
  path           = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  tenant_id      = "%s"
  client_id      = "%s"
  client_secret  = "%s"
  environment    = "AzurePublicCloud"
}
`, mount, kmsName, keyVaultName,
		os.Getenv("AZURE_TENANT_ID"),
		os.Getenv("AZURE_CLIENT_ID"),
		os.Getenv("AZURE_CLIENT_SECRET"))
}

func testKeymgmtAzureKMSConfigWithEnvironment(mount, kmsName, keyVaultName, environment string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_azure_kms" "test" {
  path           = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  tenant_id      = "%s"
  client_id      = "%s"
  client_secret  = "%s"
  environment    = %q
}
`, mount, kmsName, keyVaultName,
		os.Getenv("AZURE_TENANT_ID"),
		os.Getenv("AZURE_CLIENT_ID"),
		os.Getenv("AZURE_CLIENT_SECRET"),
		environment)
}

func testKeymgmtAzureKMSConfigMultiple(mount, kmsName1, kmsName2, keyVaultName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_azure_kms" "test1" {
  path           = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  tenant_id      = "%s"
  client_id      = "%s"
  client_secret  = "%s"
  environment    = "AzurePublicCloud"
}

resource "vault_keymgmt_azure_kms" "test2" {
  path           = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  tenant_id      = "%s"
  client_id      = "%s"
  client_secret  = "%s"
  environment    = "AzureUSGovernmentCloud"
}
`, mount, kmsName1, keyVaultName,
		os.Getenv("AZURE_TENANT_ID"),
		os.Getenv("AZURE_CLIENT_ID"),
		os.Getenv("AZURE_CLIENT_SECRET"),
		kmsName2, keyVaultName,
		os.Getenv("AZURE_TENANT_ID"),
		os.Getenv("AZURE_CLIENT_ID"),
		os.Getenv("AZURE_CLIENT_SECRET"))
}
