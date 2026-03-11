// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccKeymgmtKeyRotate_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key_rotate"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKeyRotate_initialConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttrSet(resourceName, "latest_version"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtKeyRotateImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

func TestAccKeymgmtKeyRotate_multiple(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key_rotate"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKeyRotate_singleRotation(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttrSet(resourceName, "latest_version"),
				),
			},
			{
				Config: testKeymgmtKeyRotate_multipleRotations(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
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
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_key_rotate" "test" {
  mount = vault_mount.keymgmt.path
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
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_key_rotate" "test" {
  mount = vault_mount.keymgmt.path
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
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_key_rotate" "test" {
  mount = vault_mount.keymgmt.path
  name = vault_keymgmt_key.test.name
}

resource "vault_keymgmt_key_rotate" "second" {
  mount = vault_mount.keymgmt.path
  name = vault_keymgmt_key.test.name
  
  depends_on = [vault_keymgmt_key_rotate.test]
}
`, mount, keyName)
}

func testAccKeymgmtKeyRotateImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		mount := rs.Primary.Attributes[consts.FieldMount]
		name := rs.Primary.Attributes[consts.FieldName]
		return fmt.Sprintf("%s/key/%s/rotate", mount, name), nil
	}
}
