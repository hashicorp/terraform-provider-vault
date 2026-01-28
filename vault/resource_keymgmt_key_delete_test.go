// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKeymgmtKeyDelete_basic(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key_delete"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKeyDelete_basicConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
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

func TestAccKeymgmtKeyDelete_deniedWithoutDeletionAllowed(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtKeyDelete_deniedConfig(mount, keyName),
				ExpectError: regexp.MustCompile("deletion_allowed is not set to true"),
			},
		},
	})
}

func testKeymgmtKeyDelete_basicConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  path             = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_key_delete" "test" {
  path = vault_mount.keymgmt.path
  name = vault_keymgmt_key.test.name
  
  depends_on = [vault_keymgmt_key.test]
}
`, mount, keyName)
}

func testKeymgmtKeyDelete_forceDeleteConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  path = vault_mount.keymgmt.path
  name = %q
  type = "aes256-gcm96"
  # deletion_allowed = false (default)
}

resource "vault_keymgmt_key_delete" "test" {
  path = vault_mount.keymgmt.path
  name = vault_keymgmt_key.test.name
  
  depends_on = [vault_keymgmt_key.test]
}
`, mount, keyName)
}

func testKeymgmtKeyDelete_deniedConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  path = vault_mount.keymgmt.path
  name = %q
  type = "aes256-gcm96"
  # deletion_allowed = false (default)
}

resource "vault_keymgmt_key_delete" "test" {
  path = vault_mount.keymgmt.path
  name = vault_keymgmt_key.test.name
  
  depends_on = [vault_keymgmt_key.test]
}
`, mount, keyName)
}
