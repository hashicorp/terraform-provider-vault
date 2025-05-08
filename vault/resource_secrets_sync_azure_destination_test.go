// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAzureSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-azure")

	resourceName := "vault_secrets_sync_azure_destination.test"

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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretsSyncDestinationConfig_initial(keyVaultURI, clientID, clientSecret, tenantID, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, clientSecret),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, clientID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, tenantID),
					resource.TestCheckResourceAttr(resourceName, fieldKeyVaultURI, keyVaultURI),
					resource.TestCheckResourceAttr(resourceName, fieldCloud, "cloud"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
				),
			},
			{
				Config: testAzureSecretsSyncDestinationConfig_updated(keyVaultURI, clientID, clientSecret, tenantID, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientSecret, clientSecret),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, clientID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, tenantID),
					resource.TestCheckResourceAttr(resourceName, fieldKeyVaultURI, keyVaultURI),
					resource.TestCheckResourceAttr(resourceName, fieldCloud, "cloud"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, secretsKeyTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-key"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.baz", "bux"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldClientSecret,
			),
		},
	})
}

func testAzureSecretsSyncDestinationConfig_initial(keyVaultURI, clientID, clientSecret, tenantID, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_azure_destination" "test" {
  name                 = "%s"
  key_vault_uri        = "%s"
  client_id            = "%s"
  client_secret        = "%s"
  tenant_id            = "%s"
  %s
}
`, destName, keyVaultURI, clientID, clientSecret, tenantID, testSecretsSyncDestinationCommonConfig(templ, true, true, false))

	return ret
}

func testAzureSecretsSyncDestinationConfig_updated(keyVaultURI, clientID, clientSecret, tenantID, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_azure_destination" "test" {
  name                 = "%s"
  key_vault_uri        = "%s"
  client_id            = "%s"
  client_secret        = "%s"
  tenant_id            = "%s"
  %s
}
`, destName, keyVaultURI, clientID, clientSecret, tenantID, testSecretsSyncDestinationCommonConfig(templ, true, true, true))

	return ret
}
