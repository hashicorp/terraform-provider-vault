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

func TestAWSSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest")

	resourceName := "vault_aws_secrets_sync_destination.test"

	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testAWSSecretsSyncDestinationConfig(accessKey, secretKey, region, destName),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, accessKey),
					resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, secretKey),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
				),
			},
		},
	})
}

func testAWSSecretsSyncDestinationConfig(accessKey, secretKey, region, destName string) string {
	ret := fmt.Sprintf(`
resource "vault_aws_secrets_sync_destination" "test" {
  name              = "%s"
  access_key_id     = "%s"
  secret_access_key = "%s"
  region            = "%s"
}
`, destName, accessKey, secretKey, region)

	return ret
}
