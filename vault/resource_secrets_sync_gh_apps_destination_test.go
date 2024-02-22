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

func TestGithubAppsSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-github-apps")

	resourceName := "vault_secrets_sync_github_apps_destination.test"

	values := testutil.SkipTestEnvUnset(t,
		"GITHUB_APPS_PRIVATE_KEY",
		"GITHUB_APPS_ID",
	)

	privateKey := values[0]
	appID := values[1]

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testGithubAppsSecretsSyncDestinationConfig_initial(privateKey, appID, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKey, privateKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAppID, appID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
				),
			},
			{
				Config: testGithubAppsSecretsSyncDestinationConfig_updated(privateKey, appID, destName, updatedSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKey, privateKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAppID, appID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, updatedSecretsSyncTemplate),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldPrivateKey,
			),
		},
	})
}

func testGithubAppsSecretsSyncDestinationConfig_initial(privateKey, appID, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_github_apps_destination" "test" {
  name           = "%s"
  private_key    = "%s"
  app_id         = "%s"
  %s
}
`, destName, privateKey, appID, testSecretsSyncDestinationCommonConfig(templ, true, false, false))

	return ret
}

func testGithubAppsSecretsSyncDestinationConfig_updated(privateKey, appID, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_github_apps_destination" "test" {
  name           = "%s"
  private_key    = "%s"
  app_id         = "%s"
  %s
}
`, destName, privateKey, appID, testSecretsSyncDestinationCommonConfig(templ, true, false, true))

	return ret
}
