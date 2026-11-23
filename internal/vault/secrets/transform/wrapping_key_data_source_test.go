// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccTransformWrappingKeyDataSource_basic(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testConfigTransformWrappingKeyDataSource(mount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_transform_wrapping_key.test", "mount", mount),
					resource.TestMatchResourceAttr("data.vault_transform_wrapping_key.test", "public_key", regexp.MustCompile(`^-----BEGIN PUBLIC KEY-----`)),
				),
			},
		},
	})
}

func testConfigTransformWrappingKeyDataSource(mount string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "transform"
}

data "vault_transform_wrapping_key" "test" {
  mount = vault_mount.test.path
}
`, mount)
}
