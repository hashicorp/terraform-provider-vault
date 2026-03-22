// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"os"
	"regexp"
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
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLatestVersion),
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
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLatestVersion),
				),
			},
			{
				Config: testKeymgmtKeyRotate_multipleRotations(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					// Verify that latest_version has increased
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLatestVersion),
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

func TestAccKeymgmtKeyRotate_namespace(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	namespace := acctest.RandomWithPrefix("test-namespace")
	resourceType := "vault_keymgmt_key_rotate"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKeyRotate_namespaceConfig(namespace, mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespace),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLatestVersion),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtKeyRotateImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, namespace)
				},
			},
			{
				// Cleanup step: unset the env var and verify no drift
				Config:   testKeymgmtKeyRotate_namespaceConfig(namespace, mount, keyName),
				PlanOnly: true,
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
			},
		},
	})
}

func testKeymgmtKeyRotate_namespaceConfig(namespace, mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_mount" "keymgmt" {
  namespace = vault_namespace.test.path
  path      = %q
  type      = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  namespace        = vault_namespace.test.path
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_key_rotate" "test" {
  namespace = vault_namespace.test.path
  mount     = vault_mount.keymgmt.path
  name      = vault_keymgmt_key.test.name
}
`, namespace, mount, keyName)
}

func TestAccKeymgmtKeyRotate_invalidMount(t *testing.T) {
	mount := "nonexistent-mount"
	keyName := acctest.RandomWithPrefix("key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtKeyRotate_invalidMountConfig(mount, keyName),
				ExpectError: regexp.MustCompile(`no handler for route`),
			},
		},
	})
}

func TestAccKeymgmtKeyRotate_nonExistentKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := "nonexistent-key"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtKeyRotate_nonExistentKeyConfig(mount, keyName),
				ExpectError: regexp.MustCompile(`key ".*" not found`),
			},
		},
	})
}

func testKeymgmtKeyRotate_invalidMountConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_keymgmt_key_rotate" "test" {
  mount = %q
  name  = %q
}
`, mount, keyName)
}

func testKeymgmtKeyRotate_nonExistentKeyConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key_rotate" "test" {
  mount = vault_mount.keymgmt.path
  name  = %q
}
`, mount, keyName)
}
