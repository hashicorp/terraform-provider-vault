// Copyright IBM Corp. 2016, 2025
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

func TestGithubAppsSecretsSync(t *testing.T) {
	appName := acctest.RandomWithPrefix("tf-sync-github-apps")

	resourceName := "vault_secrets_sync_github_apps.test"

	values := testutil.SkipTestEnvUnset(t,
		"GITHUB_APPS_PRIVATE_KEY",
		"GITHUB_APPS_ID",
	)

	privateKey := values[0]
	appID := values[1]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testGithubAppsSecretsSyncConfig_initial(privateKey, appID, appName),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, appName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKey, privateKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAppID, appID),
				),
			},
			{
				Config: testGithubAppsSecretsSyncConfig_updated(privateKey, appID, appName),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, appName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPrivateKey, privateKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAppID, appID),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldPrivateKey,
			),
		},
	})
}

func testGithubAppsSecretsSyncConfig_initial(privateKey, appID, appName string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_github_apps" "test" {
  name           = "%s"
  private_key    = "%s"
  app_id         = "%s"
}
`, appName, privateKey, appID)

	return ret
}

func testGithubAppsSecretsSyncConfig_updated(privateKey, appID, appName string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_github_apps" "test" {
  name           = "%s"
  private_key    = "%s"
  app_id         = "%s"
}
`, appName, privateKey, appID)

	return ret
}
