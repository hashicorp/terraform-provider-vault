// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
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
					resource.TestCheckResourceAttrSet(resourceName, "id"),
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
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldReplicaRegions,
			),
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
