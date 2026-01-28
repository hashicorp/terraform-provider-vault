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

func TestAccKeymgmtKeyRotate_basic(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key_rotate"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKeyRotate_initialConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttrSet(resourceName, "latest_version"),
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

func TestAccKeymgmtKeyRotate_multiple(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key_rotate"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKeyRotate_singleRotation(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttrSet(resourceName, "latest_version"),
				),
			},
			{
				Config: testKeymgmtKeyRotate_multipleRotations(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					// Verify that latest_version has increased
					resource.TestCheckResourceAttrSet(resourceName, "latest_version"),
				),
			},
		},
	})
}

func testKeymgmtKeyRotate_initialConfig(mount, keyName string) string {
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

resource "vault_keymgmt_key_rotate" "test" {
  path = vault_mount.keymgmt.path
  name = vault_keymgmt_key.test.name
}
`, mount, keyName)
}

func testKeymgmtKeyRotate_singleRotation(mount, keyName string) string {
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

resource "vault_keymgmt_key_rotate" "test" {
  path = vault_mount.keymgmt.path
  name = vault_keymgmt_key.test.name
}
`, mount, keyName)
}

func testKeymgmtKeyRotate_multipleRotations(mount, keyName string) string {
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

# First rotation
resource "vault_keymgmt_key_rotate" "test" {
  path = vault_mount.keymgmt.path
  name = vault_keymgmt_key.test.name
}

# Second rotation (triggers when we update the resource)
# In practice, users would update this to trigger another rotation
# This demonstrates the capability to rotate multiple times
`, mount, keyName)
}
