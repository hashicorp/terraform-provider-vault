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

func TestVercelSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-vercel")

	resourceName := "vault_vercel_secrets_sync_destination.test"

	values := testutil.SkipTestEnvUnset(t,
		"VERCEL_ACCESS_TOKEN",
		"VERCEL_PROJECT_ID",
	)
	accessToken := values[0]
	projectID := values[1]
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testVercelSecretsSyncDestinationConfig(accessToken, projectID, destName),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessToken, accessToken),
					resource.TestCheckResourceAttr(resourceName, fieldProjectID, projectID),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.0", "development"),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.1", "preview"),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.2", "production"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessToken,
			),
		},
	})
}

func testVercelSecretsSyncDestinationConfig(accessToken, projectID, destName string) string {
	ret := fmt.Sprintf(`
resource "vault_vercel_secrets_sync_destination" "test" {
  name                    = "%s"
  access_token            = "%s"
  project_id              = "%s"
  deployment_environments = ["development", "preview", "production"]
}
`, destName, accessToken, projectID)

	return ret
}
