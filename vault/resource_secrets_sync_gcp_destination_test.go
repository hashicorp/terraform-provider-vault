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

func TestGCPSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-gcp")

	resourceName := "vault_secrets_sync_gcp_destination.test"

	credentials, _ := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretsSyncDestinationConfig_initial(credentials, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentials, credentials),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, gcpSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, "gcp-project-id"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
				),
			},
			{
				Config: testGCPSecretsSyncDestinationConfig_updated(credentials, destName, updatedSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentials, credentials),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, updatedSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, gcpSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProjectID, "gcp-project-id-updated"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.baz", "bux"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldCredentials),
		},
	})
}

func testGCPSecretsSyncDestinationConfig_initial(credentials, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                 = "%s"
  project_id  	= "gcp-project-id"
  credentials          = <<CREDS
%sCREDS
  %s
}
`, destName, credentials, testSecretsSyncDestinationCommonConfig(templ, false, true, false))

	return ret
}

func testGCPSecretsSyncDestinationConfig_updated(credentials, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                 = "%s"
  project_id  	= "gcp-project-id-updated"
  credentials          = <<CREDS
%sCREDS
  %s
}
`, destName, credentials, testSecretsSyncDestinationCommonConfig(templ, true, true, true))

	return ret
}
