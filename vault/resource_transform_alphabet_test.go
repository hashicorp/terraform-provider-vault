// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccTransformAlphabet(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testTransformAlphabetDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransformAlphabet_basicConfig(path, "numerics", "0123456789"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_alphabet.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_alphabet.test", "name", "numerics"),
					resource.TestCheckResourceAttr("vault_transform_alphabet.test", "alphabet", "0123456789"),
				),
			},
			{
				Config: testTransformAlphabet_basicConfig(path, "numerics", "012345678"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transform_alphabet.test", "path", path),
					resource.TestCheckResourceAttr("vault_transform_alphabet.test", "name", "numerics"),
					resource.TestCheckResourceAttr("vault_transform_alphabet.test", "alphabet", "012345678"),
				),
			},
			{
				ResourceName:      "vault_transform_alphabet.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testTransformAlphabetDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_alphabet" {
			continue
		}
		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for alphabet %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("alphabet %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testTransformAlphabet_basicConfig(path, name, alphabet string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_alphabet" "test" {
  path     = vault_mount.mount_transform.path
  name     = "%s"
  alphabet = "%s"
}
`, path, name, alphabet)
}
