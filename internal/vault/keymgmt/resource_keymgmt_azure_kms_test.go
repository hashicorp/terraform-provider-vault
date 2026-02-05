// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtAzureKMS(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	// Skip if Azure credentials are not available
	if os.Getenv("AZURE_TENANT_ID") == "" {
		t.Skip("AZURE_TENANT_ID not set, skipping Azure KMS test")
	}

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	kmsName := acctest.RandomWithPrefix("azurekms")
	resourceType := "vault_keymgmt_azure_kms"
	resourceName := resourceType + ".test"

	keyVaultName := os.Getenv("AZURE_KEYVAULT_NAME")
	if keyVaultName == "" {
		keyVaultName = "test-keyvault"
	}

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
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"client_id",
				"client_secret",
			),
		},
	})
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
