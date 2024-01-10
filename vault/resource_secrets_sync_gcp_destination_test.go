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

	resourceName := "vault_gcp_secrets_sync_destination.test"

	values := testutil.SkipTestEnvUnset(t,
		"GOOGLE_APPLICATION_CREDENTIALS",
	)
	credentials := values[0]

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretsSyncDestinationConfig(credentials, destName),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentials, credentials),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldCredentials),
		},
	})
}

func testGCPSecretsSyncDestinationConfig(credentials, destName string) string {
	ret := fmt.Sprintf(`
resource "vault_gcp_secrets_sync_destination" "test" {
  name              = "%s"
  credentials       = "%s"
}
`, destName, credentials)

	return ret
}
