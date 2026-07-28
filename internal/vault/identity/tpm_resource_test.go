// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package identity_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

func TestAccIdentityTPM(t *testing.T) {
	name := acctest.RandomWithPrefix("tpm")
	renamedName := acctest.RandomWithPrefix("tpm")
	resourceName := "vault_identity_tpm.test"
	publicKey := testTPMPublicKey(t)
	var originalTPMID string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion210)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityTPMConfig(name, publicKey, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "tpm_ek_public_key", publicKey+"\n"),
					resource.TestCheckResourceAttr(resourceName, "disabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "tpm_id"),
					resource.TestCheckResourceAttrWith(resourceName, "tpm_id", func(value string) error {
						originalTPMID = value
						return nil
					}),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccIdentityTPMConfig(renamedName, publicKey, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", renamedName),
					resource.TestCheckResourceAttr(resourceName, "disabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "tpm_id"),
					resource.TestCheckResourceAttrWith(resourceName, "tpm_id", func(value string) error {
						if value != originalTPMID {
							return fmt.Errorf("expected tpm_id %q after rename, got %q", originalTPMID, value)
						}
						return nil
					}),
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
				Config: testAccIdentityTPMConfig(renamedName, publicKey, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", renamedName),
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

func testTPMPublicKey(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
	return strings.TrimSuffix(string(pemBytes), "\n")
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
