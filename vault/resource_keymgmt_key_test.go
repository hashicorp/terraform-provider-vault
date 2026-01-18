// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtKey_basic(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_initialConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "false"),
					resource.TestCheckResourceAttr(resourceName, "allow_plaintext_backup", "false"),
					resource.TestCheckResourceAttr(resourceName, "allow_generate_key", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "latest_version"),
				),
			},
			{
				Config: testKeymgmtKey_updatedConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceName, "allow_plaintext_backup", "true"),
					resource.TestCheckResourceAttr(resourceName, "allow_generate_key", "false"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"replica_regions"},
			},
		},
	})
}

func testKeymgmtKey_initialConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  path = vault_mount.keymgmt.path
  name = %q
  type = "aes256-gcm96"
}
`, mount, keyName)
}

func testKeymgmtKey_updatedConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  path                   = vault_mount.keymgmt.path
  name                   = %q
  type                   = "aes256-gcm96"
  deletion_allowed       = true
  allow_plaintext_backup = true
  allow_generate_key     = false
}
`, mount, keyName)
}
