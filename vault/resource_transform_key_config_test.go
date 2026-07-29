// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccTransformKeyConfig(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	name := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_transform_key_configuration.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testTransformKeyConfig_basic(path, name, 1, "24h"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "min_decryption_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "auto_rotate_period", "24h"),
				),
			},
			{
				Config: testTransformKeyConfig_basic(path, name, 2, "48h"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "min_decryption_version", "2"),
					resource.TestCheckResourceAttr(resourceName, "auto_rotate_period", "48h"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testTransformKeyConfig_basic(path, name string, minDecryptionVersion int, autoRotatePeriod string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_key_configuration" "test" {
  path                   = vault_mount.mount_transform.path
  name                   = "%s"
  min_decryption_version = %d
  auto_rotate_period     = "%s"
}
`, path, name, minDecryptionVersion, autoRotatePeriod)
}
