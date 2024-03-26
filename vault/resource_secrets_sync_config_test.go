// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestSecretsSyncConfig(t *testing.T) {
	resourceName := "vault_secrets_sync_config.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testSecretsSyncConfig("root", true, 1),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, fieldDisabled, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldQueueCapacity, "1"),
				),
			},
			{
				Config: testSecretsSyncConfigEmpty(),
				Check: resource.ComposeTestCheckFunc(

					resource.TestCheckResourceAttr(resourceName, fieldDisabled, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldQueueCapacity, "1000000"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldDisabled,
				fieldQueueCapacity,
			),
		},
	})

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config:      testSecretsSyncConfig("non-root-namespace", false, 100000),
				ExpectError: regexp.MustCompile(".*this API is reserved to the root namespace.*"),
			},
		},
	})
}

func testSecretsSyncConfig(namespace string, disabled bool, queueCapacity int) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_config" "test" {
  namespace      = "%s"
  disabled       = %t
  queue_capacity = %d
}
`, namespace, disabled, queueCapacity)

	return ret
}

func testSecretsSyncConfigEmpty() string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_config" "test" {
}
`)

	return ret
}
