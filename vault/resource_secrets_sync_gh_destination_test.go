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

const secretsKeyTemplate = "VAULT_{{ .MountAccessor | uppercase }}_{{ .SecretKey | uppercase }}"

func TestGithubSecretsSyncDestination(t *testing.T) {
	var p *schema.Provider
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
				),
			},
			{
				Config: testGithubSecretsSyncDestinationConfig_updated(accessToken, repoOwner, repoName, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessToken, accessToken),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryOwner, repoOwner),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryName, repoName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, secretsKeyTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-key"),
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
  %s
}
`, destName, accessToken, repoOwner, repoName, testSecretsSyncDestinationCommonConfig(templ, true, false, true))

	return ret
}
