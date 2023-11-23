// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAzureSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest")

	resourceName := "vault_azure_secrets_sync_destination.test"

	values := testutil.SkipTestEnvUnset(t,
		"AZURE_KEY_VAULT_URI",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_TENANT_ID",
	)
	keyVaultURI := values[0]
	clientID := values[1]
	clientSecret := values[2]
	tenantID := values[3]

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretsSyncDestinationConfig(keyVaultURI, clientID, clientSecret, tenantID, destName),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, clientSecret),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, clientID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, tenantID),
					resource.TestCheckResourceAttr(resourceName, fieldKeyVaultURI, keyVaultURI),
					resource.TestCheckResourceAttr(resourceName, fieldCloud, "cloud"),
				),
			},
		},
	})
}

func testAzureSecretsSyncDestinationConfig(keyVaultURI, clientID, clientSecret, tenantID, destName string) string {
	ret := fmt.Sprintf(`
resource "vault_azure_secrets_sync_destination" "test" {
  name              = "%s"
  key_vault_uri     = "%s"
  client_id         = "%s"
  client_secret     = "%s"
  tenant_id         = "%s"
}
`, destName, keyVaultURI, clientID, clientSecret, tenantID)

	return ret
}
