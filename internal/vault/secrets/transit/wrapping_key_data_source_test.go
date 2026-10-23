// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccTransitWrappingKeyDataSource_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("transit-mount")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testConfigTransitWrappingKeyDataSource(mount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_secret_backend_wrapping_key.test", "mount", mount),
					resource.TestMatchResourceAttr("data.vault_secret_backend_wrapping_key.test", "public_key", regexp.MustCompile(`^-----BEGIN PUBLIC KEY-----`)),
				),
			},
		},
	})
}

func testConfigTransitWrappingKeyDataSource(mount string) string {
	return fmt.Sprintf(`
%s

data "vault_secret_backend_wrapping_key" "test" {
  mount = vault_mount.test.path
}
`, testConfigTransitMount(mount))
}
