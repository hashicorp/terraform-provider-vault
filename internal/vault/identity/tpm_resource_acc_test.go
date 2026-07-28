// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package identity_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
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

const (
	tpmPublicKeyOne = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAu5YIWbS0JtKO6mgJrmMa24RHTACn2BF3OOd9N7BxtIA=
-----END PUBLIC KEY-----`
	tpmPublicKeyTwo = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhshc3hm6ZNkBRDWdPDLKAf1mHGq9EsWx8MlidOWiZdw=
-----END PUBLIC KEY-----`
)

func TestAccIdentityTPM(t *testing.T) {
	name := acctest.RandomWithPrefix("tpm")
	resourceName := "vault_identity_tpm.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion210)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityTPMConfig(name, tpmPublicKeyOne, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "tpm_ek_public_key", tpmPublicKeyOne+"\n"),
					resource.TestCheckResourceAttr(resourceName, "disabled", "false"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccIdentityTPMConfig(name, tpmPublicKeyOne, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "disabled", "true"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateIdFunc: testAccIdentityTPMImportStateIdFunc(resourceName),
				ImportStateVerify: true,
			},
			{
				Config: testAccIdentityTPMConfigDestroyOnly(),
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

func TestAccIdentityTPMGroup(t *testing.T) {
	groupName := acctest.RandomWithPrefix("tpm-group")
	tpmOneName := acctest.RandomWithPrefix("tpm")
	tpmTwoName := acctest.RandomWithPrefix("tpm")
	resourceName := "vault_identity_tpm_group.test"

	tpmOneID, err := tpmIDFromPublicKey(tpmPublicKeyOne)
	if err != nil {
		t.Fatalf("failed to compute TPM 1 ID: %v", err)
	}
	tpmTwoID, err := tpmIDFromPublicKey(tpmPublicKeyTwo)
	if err != nil {
		t.Fatalf("failed to compute TPM 2 ID: %v", err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion210)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityTPMGroupConfig(groupName, tpmOneName, tpmTwoName, nil),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", groupName),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "0"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccIdentityTPMGroupConfig(groupName, tpmOneName, tpmTwoName, []string{tpmOneID, tpmTwoID}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", groupName),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "member_tpm_ids.*", tpmOneID),
					resource.TestCheckTypeSetElemAttr(resourceName, "member_tpm_ids.*", tpmTwoID),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateIdFunc: testAccIdentityTPMGroupImportStateIdFunc(resourceName),
				ImportStateVerify: true,
			},
			{
				Config: testAccIdentityTPMGroupConfigDestroyOnly(tpmOneName, tpmTwoName),
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

func testAccIdentityTPMConfig(name, publicKey string, disabled bool) string {
	return fmt.Sprintf(`
resource "vault_identity_tpm" "test" {
  name = %q
  tpm_ek_public_key = <<EOT
%s
EOT
  disabled = %t
}
`, name, publicKey, disabled)
}

func testAccIdentityTPMConfigDestroyOnly() string {
	return `
locals {
  noop = "noop"
}
`
}

func testAccIdentityTPMGroupConfig(groupName, tpmOneName, tpmTwoName string, members []string) string {
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
`, tpmOneName, tpmPublicKeyOne, tpmTwoName, tpmPublicKeyTwo, groupName, membersAttr)
}

func testAccIdentityTPMGroupConfigDestroyOnly(tpmOneName, tpmTwoName string) string {
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
`, tpmOneName, tpmPublicKeyOne, tpmTwoName, tpmPublicKeyTwo)
}

func tpmIDFromPublicKey(publicKey string) (string, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(publicKey)))
	if block == nil {
		return "", fmt.Errorf("invalid PEM public key")
	}

	canonical := string(pem.EncodeToMemory(block))
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

func testAccIdentityTPMImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return rs.Primary.Attributes["name"], nil
	}
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
