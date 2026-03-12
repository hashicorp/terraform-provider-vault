// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
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
	tenantID, clientID, clientSecret, keyVaultName := testutil.GetTestAzureKMSCreds(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("azurekms")
	resourceType := "vault_keymgmt_azure_kms"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAzureKMSConfig(mount, kmsName, keyVaultName, tenantID, clientID, clientSecret),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", keyVaultName),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtAzureKMSImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCredentialsWO,
					consts.FieldCredentialsWOVersion,
				},
			},
		},
	})
}

func TestAccKeymgmtAzureKMS_update(t *testing.T) {
	tenantID, clientID, clientSecret, keyVaultName := testutil.GetTestAzureKMSCreds(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("azurekms")
	resourceType := "vault_keymgmt_azure_kms"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAzureKMSConfig(mount, kmsName, keyVaultName, tenantID, clientID, clientSecret),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", keyVaultName),
				),
			},
			{
				Config: testKeymgmtAzureKMSConfigWithEnvironment(mount, kmsName, keyVaultName, tenantID, clientID, clientSecret, "AzureUSGovernmentCloud"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
					resource.TestCheckResourceAttr(resourceName, "key_collection", keyVaultName),
				),
			},
		},
	})
}

func TestAccKeymgmtAzureKMS_environments(t *testing.T) {
	tenantID, clientID, clientSecret, keyVaultName := testutil.GetTestAzureKMSCreds(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")

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
						Config: testKeymgmtAzureKMSConfigWithEnvironment(mount, kmsName, keyVaultName, tenantID, clientID, clientSecret, tc.env),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
							resource.TestCheckResourceAttr(resourceName, consts.FieldName, kmsName),
							resource.TestCheckResourceAttr(resourceName, "key_collection", keyVaultName),
						),
					},
				},
			})
		})
	}
}

func TestAccKeymgmtAzureKMS_multiple(t *testing.T) {
	tenantID, clientID, clientSecret, keyVaultName := testutil.GetTestAzureKMSCreds(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName1 := acctest.RandomWithPrefix("azurekms-1")
	kmsName2 := acctest.RandomWithPrefix("azurekms-2")
	resourceName1 := "vault_keymgmt_azure_kms.test1"
	resourceName2 := "vault_keymgmt_azure_kms.test2"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtAzureKMSConfigMultiple(mount, kmsName1, kmsName2, keyVaultName, tenantID, clientID, clientSecret),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldName, kmsName1),
					resource.TestCheckResourceAttr(resourceName1, "key_collection", keyVaultName),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldName, kmsName2),
					resource.TestCheckResourceAttr(resourceName2, "key_collection", keyVaultName),
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
		mount := rs.Primary.Attributes[consts.FieldMount]
		name := rs.Primary.Attributes[consts.FieldName]
		return fmt.Sprintf("%s/kms/%s", mount, name), nil
	}
}

func testKeymgmtAzureKMSConfig(mount, kmsName, keyVaultName, tenantID, clientID, clientSecret string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_azure_kms" "test" {
  mount          = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  credentials_wo = {
    tenant_id     = "%s"
    client_id     = "%s"
    client_secret = "%s"
  }
  credentials_wo_version = 1
}
`, mount, kmsName, keyVaultName, tenantID, clientID, clientSecret)
}

func testKeymgmtAzureKMSConfigWithEnvironment(mount, kmsName, keyVaultName, tenantID, clientID, clientSecret, environment string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_azure_kms" "test" {
  mount          = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  credentials_wo = {
    tenant_id     = "%s"
    client_id     = "%s"
    client_secret = "%s"
    environment   = %q
  }
  credentials_wo_version = 1
}
`, mount, kmsName, keyVaultName, tenantID, clientID, clientSecret, environment)
}

func testKeymgmtAzureKMSConfigMultiple(mount, kmsName1, kmsName2, keyVaultName, tenantID, clientID, clientSecret string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_azure_kms" "test1" {
  mount          = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  credentials_wo = {
    tenant_id     = "%s"
    client_id     = "%s"
    client_secret = "%s"
    environment   = "AzurePublicCloud"
  }
  credentials_wo_version = 1
}

resource "vault_keymgmt_azure_kms" "test2" {
  mount          = vault_mount.keymgmt.path
  name           = %q
  key_collection = %q
  credentials_wo = {
    tenant_id     = "%s"
    client_id     = "%s"
    client_secret = "%s"
    environment   = "AzureUSGovernmentCloud"
  }
  credentials_wo_version = 1
}
`, mount, kmsName1, keyVaultName, tenantID, clientID, clientSecret,
		kmsName2, keyVaultName, tenantID, clientID, clientSecret)
}
