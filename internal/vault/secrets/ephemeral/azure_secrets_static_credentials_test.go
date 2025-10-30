// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceAzureAccessStaticCredentialsAzureRoles_basic(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)

	if conf.AppObjectID == "" {
		t.Skip("AZURE_APP_OBJECT_ID must be set to run Azure static role tests")
	}

	backend := acctest.RandomWithPrefix("tf-test-azure")
	role := acctest.RandomWithPrefix("tf-role")
	resourceName := "data.vault_azure_static_credentials.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAzureAccessStaticCredentialsConfig(backend, role, conf),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientID),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientSecret),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldSecretID),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.hello", "world"),
					resource.TestCheckResourceAttr(resourceName, "metadata.team", "eco"),
				),
			},
		},
	})
}

func testAccDataSourceAzureAccessStaticCredentialsConfig(backend, role string, conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  path            = "%[1]s"
  subscription_id = "%[2]s"
  tenant_id       = "%[3]s"
  client_id       = "%[4]s"
  client_secret   = "%[5]s"
}

resource "vault_azure_secret_backend_static_role" "role" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "%[6]s"
  application_object_id = "%[7]s"
  ttl                   = 31536000

  metadata = {
    hello = "world"
    team  = "eco"
  }
}

ephemeral "vault_azure_static_credentials" "read" {
  backend = vault_azure_secret_backend.azure.path
  role    = vault_azure_secret_backend_static_role.imported.role
}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, role, conf.AppObjectID)
}
