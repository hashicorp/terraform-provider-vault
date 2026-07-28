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

// tpmPublicKeyOne and tpmPublicKeyTwo are test EK public keys shared across TPM
// and TPMGroup tests.
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
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion203)
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
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccIdentityTPMImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
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

func testAccIdentityTPMImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return rs.Primary.Attributes["name"], nil
	}
}

// tpmIDFromPublicKey computes the TPM record ID (SHA256 of canonical PEM) the
// same way Vault does, so tests can pre-compute expected member_tpm_ids values.
func tpmIDFromPublicKey(publicKey string) (string, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(publicKey)))
	if block == nil {
		return "", fmt.Errorf("invalid PEM public key")
	}

	canonical := string(pem.EncodeToMemory(block))
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}
