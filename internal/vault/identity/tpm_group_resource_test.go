// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package identity_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccIdentityTPMGroup(t *testing.T) {
	groupName := acctest.RandomWithPrefix("tpm-group")
	renamedGroupName := acctest.RandomWithPrefix("tpm-group")
	tpmOneName := acctest.RandomWithPrefix("tpm")
	tpmTwoName := acctest.RandomWithPrefix("tpm")
	resourceName := "vault_identity_tpm_group.test"
	tpmOnePublicKey := testTPMPublicKey(t)
	tpmTwoPublicKey := testTPMPublicKey(t)
	var tpmGroupID string

	tpmOneID, err := tpmIDFromPublicKey(tpmOnePublicKey)
	if err != nil {
		t.Fatalf("failed to compute TPM 1 ID: %v", err)
	}
	tpmTwoID, err := tpmIDFromPublicKey(tpmTwoPublicKey)
	if err != nil {
		t.Fatalf("failed to compute TPM 2 ID: %v", err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityTPMGroupConfig(groupName, tpmOneName, tpmTwoName, nil, tpmOnePublicKey, tpmTwoPublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", groupName),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "tpm_group_id"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccIdentityTPMGroupConfig(groupName, tpmOneName, tpmTwoName, []string{tpmOneID, tpmTwoID}, tpmOnePublicKey, tpmTwoPublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", groupName),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "member_tpm_ids.*", tpmOneID),
					resource.TestCheckTypeSetElemAttr(resourceName, "member_tpm_ids.*", tpmTwoID),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("not found: %s", resourceName)
						}
						tpmGroupID = rs.Primary.Attributes["tpm_group_id"]
						if tpmGroupID == "" {
							return fmt.Errorf("empty tpm_group_id")
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccIdentityTPMGroupConfig(renamedGroupName, tpmOneName, tpmTwoName, []string{tpmOneID, tpmTwoID}, tpmOnePublicKey, tpmTwoPublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", renamedGroupName),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "member_tpm_ids.*", tpmOneID),
					resource.TestCheckTypeSetElemAttr(resourceName, "member_tpm_ids.*", tpmTwoID),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("not found: %s", resourceName)
						}
						if rs.Primary.Attributes["tpm_group_id"] != tpmGroupID {
							return fmt.Errorf("tpm_group_id changed across rename: got %q want %q",
								rs.Primary.Attributes["tpm_group_id"], tpmGroupID)
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccIdentityTPMGroupImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
			{
				Config: testAccIdentityTPMGroupConfigDestroyOnly(tpmOneName, tpmTwoName, tpmOnePublicKey, tpmTwoPublicKey),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectNonEmptyPlan(),
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroy),
					},
				},
			},
		},
	})
}

func testAccIdentityTPMGroupConfig(groupName, tpmOneName, tpmTwoName string, members []string, tpmOnePublicKey, tpmTwoPublicKey string) string {
	var membersAttr string
	if len(members) > 0 {
		var quoted []string
		for _, id := range members {
			quoted = append(quoted, fmt.Sprintf("%q", id))
		}
		membersAttr = fmt.Sprintf("  member_tpm_ids = [%s]\n", strings.Join(quoted, ", "))
	}

	return fmt.Sprintf(`
resource "vault_identity_tpm" "one" {
  name = %q
  tpm_ek_public_key = <<EOT
%s
EOT
}

resource "vault_identity_tpm" "two" {
  name = %q
  tpm_ek_public_key = <<EOT
%s
EOT
}

resource "vault_identity_tpm_group" "test" {
  name = %q
%s}
`, tpmOneName, tpmOnePublicKey, tpmTwoName, tpmTwoPublicKey, groupName, membersAttr)
}

func testAccIdentityTPMGroupConfigDestroyOnly(tpmOneName, tpmTwoName, tpmOnePublicKey, tpmTwoPublicKey string) string {
	return fmt.Sprintf(`
resource "vault_identity_tpm" "one" {
  name = %q
  tpm_ek_public_key = <<EOT
%s
EOT
}

resource "vault_identity_tpm" "two" {
  name = %q
  tpm_ek_public_key = <<EOT
%s
EOT
}
`, tpmOneName, tpmOnePublicKey, tpmTwoName, tpmTwoPublicKey)
}

func testAccIdentityTPMGroupImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return rs.Primary.Attributes["name"], nil
	}
}
