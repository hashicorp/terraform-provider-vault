// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccKeymgmtKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_initialConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "false"),
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
				),
			},
			{
				Config: testKeymgmtKey_withReplicaRegions(mount, keyName, []string{"us-west-1", "us-east-1"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, "replica_regions.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "replica_regions.*", "us-west-1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "replica_regions.*", "us-east-1"),
				),
			},
			{
				Config: testKeymgmtKey_withReplicaRegions(mount, keyName, []string{"eu-west-1"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "replica_regions.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "replica_regions.*", "eu-west-1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionReplace),
					},
				},
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore: []string{
					consts.FieldReplicaRegions,
				},
			},
		},
	})
}

func testAccKeymgmtKeyImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		path := rs.Primary.Attributes[consts.FieldPath]
		name := rs.Primary.Attributes[consts.FieldName]
		return fmt.Sprintf("%s/key/%s", path, name), nil
	}
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
  path             = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}
`, mount, keyName)
}

func testKeymgmtKey_withReplicaRegions(mount, keyName string, regions []string) string {
	regionsList := make([]string, len(regions))
	for i, region := range regions {
		regionsList[i] = fmt.Sprintf("%q", region)
	}
	regionsStr := strings.Join(regionsList, ", ")

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
  replica_regions  = [%s]
}
`, mount, keyName, regionsStr)
}

func TestAccKeymgmtKey_multiple(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	key1Name := acctest.RandomWithPrefix("key1")
	key2Name := acctest.RandomWithPrefix("key2")
	resourceType := "vault_keymgmt_key"
	resourceName1 := resourceType + ".test1"
	resourceName2 := resourceType + ".test2"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_multipleConfig(mount, key1Name, key2Name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldName, key1Name),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName1, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldName, key2Name),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldType, "rsa-2048"),
					resource.TestCheckResourceAttr(resourceName2, "deletion_allowed", "true"),
				),
			},
		},
	})
}

func TestAccKeymgmtKey_namespace(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	namespace := acctest.RandomWithPrefix("test-namespace")
	resourceType := "vault_keymgmt_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_namespaceConfig(namespace, mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "true"),
				),
			},
		},
	})
}

func TestAccKeymgmtKey_validation(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtKey_invalidTypeConfig(mount, keyName),
				ExpectError: regexp.MustCompile("unsupported key type"),
			},
		},
	})
}

func testKeymgmtKey_multipleConfig(mount, key1Name, key2Name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test1" {
  path             = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_key" "test2" {
  path             = vault_mount.keymgmt.path
  name             = %q
  type             = "rsa-2048"
  deletion_allowed = true
}
`, mount, key1Name, key2Name)
}

func testKeymgmtKey_namespaceConfig(namespace, mount, keyName string) string {
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
  path             = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}
`, namespace, mount, keyName)
}

func testKeymgmtKey_invalidTypeConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  path             = vault_mount.keymgmt.path
  name             = %q
  type             = "invalid-key-type"
  deletion_allowed = true
}
`, mount, keyName)
}
