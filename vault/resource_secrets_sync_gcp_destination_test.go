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
				Config: testGCPSecretsSyncDestinationConfig(credentials, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentials, credentials),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, gcpSyncType),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_tags.foo", "bar"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldCredentials),
		},
	})
}

func testGCPSecretsSyncDestinationConfig(credentials, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_gcp_destination" "test" {
  name                 = "%s"
  credentials          = <<CREDS
%sCREDS
  secret_name_template = "%s"
  custom_tags = {
    "foo" = "bar"
  }
}
`, destName, credentials, templ)

	return ret
}
