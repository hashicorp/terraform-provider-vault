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

func TestGithubSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-gh")

	resourceName := "vault_secrets_sync_gh_destination.test"

	values := testutil.SkipTestEnvUnset(t,
		"GITHUB_ACCESS_TOKEN",
		"GITHUB_REPO_OWNER",
		"GITHUB_REPO_NAME",
	)

	accessToken := values[0]
	repoOwner := values[1]
	repoName := values[2]

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testGithubSecretsSyncDestinationConfig_initial(accessToken, repoOwner, repoName, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessToken, accessToken),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryOwner, repoOwner),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryName, repoName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAppName, "test-app-name"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInstallationID, "test-installation-id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
				),
			},
			{
				Config: testGithubSecretsSyncDestinationConfig_updated(accessToken, repoOwner, repoName, destName, updatedSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessToken, accessToken),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryOwner, repoOwner),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryName, repoName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAppName, "test-app-name-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldInstallationID, "test-installation-id-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, updatedSecretsSyncTemplate),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessToken,
			),
		},
	})
}

func testGithubSecretsSyncDestinationConfig_initial(accessToken, repoOwner, repoName, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_gh_destination" "test" {
  name                 = "%s"
  access_token         = "%s"
  repository_owner     = "%s"
  repository_name      = "%s"
  app_name             = "test-app-name"
  installation_id      = "test-installation-id"
  %s
}
`, destName, accessToken, repoOwner, repoName, testSecretsSyncDestinationCommonConfig(templ, true, false, false))

	return ret
}

func testGithubSecretsSyncDestinationConfig_updated(accessToken, repoOwner, repoName, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_gh_destination" "test" {
  name                 = "%s"
  access_token         = "%s"
  repository_owner     = "%s"
  repository_name      = "%s"
  app_name             = "test-app-name-updated"
  installation_id      = "test-installation-id-updated"
  %s
}
`, destName, accessToken, repoOwner, repoName, testSecretsSyncDestinationCommonConfig(templ, true, false, true))

	return ret
}
