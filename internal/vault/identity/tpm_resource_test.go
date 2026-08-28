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
	"regexp"
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

// TestAccIdentityTPM_versionGate verifies that TPM identity creation fails
// with an appropriate error on Vault versions < 2.2.0.
func TestAccIdentityTPM_versionGate(t *testing.T) {
	publicKey := testTPMPublicKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionGTE(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccIdentityTPMConfig(tpmConfigFields{pk: publicKey}),
				ExpectError: regexp.MustCompile(`TPM identity requires Vault version 2.2.0 or later`),
			},
		},
	})
}

// TestAccIdentityTPM validates the complete lifecycle of a TPM identity resource:
// - Creation with minimal config (tests defaults: auto-generated name, disabled=false)
// - Updating name field (verifies tpm_id remains unchanged as it's immutable)
// - Updating disabled field
// - Changing public key (verifies resource replacement due to RequiresReplace)
// - Import workflow (validates state reconstruction from Vault API)
// - Destruction
func TestAccIdentityTPM(t *testing.T) {
	renamedName := acctest.RandomWithPrefix("tpm")
	resourceName := "vault_identity_tpm.test"
	publicKey := testTPMPublicKey(t)
	var originalTPMID string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create minimal config with only required publicKey field to assert default behavior
			{
				Config: testAccIdentityTPMConfig(tpmConfigFields{pk: publicKey}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "name"),
					resource.TestCheckResourceAttr(resourceName, "tpm_ek_public_key", publicKey+"\n"),
					resource.TestCheckResourceAttr(resourceName, "disabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "0"),
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
			// Step 2: Update name
			{
				Config: testAccIdentityTPMConfig(tpmConfigFields{name: renamedName, pk: publicKey}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", renamedName),
					resource.TestCheckResourceAttr(resourceName, "disabled", "false"),
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
			// Step 3: Update disabled
			{
				Config: testAccIdentityTPMConfig(tpmConfigFields{name: renamedName, pk: publicKey, disabled: true, specifyDisabled: true}),
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
			// Step 4: Update public key while keeping every other config field the same as above
			// to assert resource is recreated and not updated
			{
				Config: testAccIdentityTPMConfig(tpmConfigFields{name: renamedName, pk: testTPMPublicKey(t), disabled: true, specifyDisabled: true}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", renamedName),
					resource.TestCheckResourceAttrWith(resourceName, "tpm_id", func(value string) error {
						if value == originalTPMID {
							return fmt.Errorf("expected tpm_id to change after public key change, but got same ID: %q", value)
						}
						return nil
					}),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionReplace),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Import test validates an existing TPM resource in Vault can be imported into Terraform state.
			// 1. Uses the resource name as the identifier
			// 2. Calls ImportState (sets name in state) then Read (populates all other fields from Vault API)
			// 3. Verifies the imported state matches the state from previous steps
			// This ensures populateDataModelFromAPI correctly reconstructs complete state from Vault.
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

// TestAccIdentityTPM_metadata verifies metadata field behavior:
// - Creating with metadata and verifying it's correctly imported from Vault
// - Omitting metadata clears it in Vault (config is the source of truth)
// - Re-adding metadata restores it
// - Setting metadata = {} explicitly clears it in Vault
func TestAccIdentityTPM_metadata(t *testing.T) {
	resourceName := "vault_identity_tpm.test"
	publicKey := testTPMPublicKey(t)
	var tpmId string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with metadata
				Config: testAccIdentityTPMConfig(tpmConfigFields{pk: publicKey, metadata: `{
					environment = "test"
					owner  = "platform-team"
				}`},
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_id", func(value string) error {
						tpmId = value
						return nil
					}),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.environment", "test"),
					resource.TestCheckResourceAttr(resourceName, "metadata.owner", "platform-team"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				// Step 2: Import to verify metadata round-trips correctly from Vault
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccIdentityTPMImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
			{
				// Step 3: Omitting metadata clears it in Vault
				Config: testAccIdentityTPMConfig(tpmConfigFields{pk: publicKey}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_id", func(value string) error {
						if value != tpmId {
							return fmt.Errorf("expected tpm_id to remain %q, got %q", tpmId, value)
						}
						return nil
					}),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "0"),
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
				// Step 4: Add metadata back to test clear below
				Config: testAccIdentityTPMConfig(tpmConfigFields{pk: publicKey, metadata: `{
					environment = "dev"
					owner  = "engineering"
				}`},
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_id", func(value string) error {
						tpmId = value
						return nil
					}),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.environment", "dev"),
					resource.TestCheckResourceAttr(resourceName, "metadata.owner", "engineering"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				// Step 5: Setting metadata = {} explicitly clears it in Vault
				Config: testAccIdentityTPMConfig(tpmConfigFields{pk: publicKey, metadata: `{}`}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_id", func(value string) error {
						if value != tpmId {
							return fmt.Errorf("expected tpm_id to remain %q, got %q", tpmId, value)
						}
						return nil
					}),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "0"),
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
		},
	})
}

type tpmConfigFields struct {
	name            string
	pk              string
	disabled        bool
	specifyDisabled bool
	metadata        string
}

func testAccIdentityTPMConfig(config tpmConfigFields) string {
	resource := fmt.Sprintf(`
resource "vault_identity_tpm" "test" {
  tpm_ek_public_key = <<EOT
%s
EOT

`, config.pk)

	if config.name != "" {
		resource += fmt.Sprintf(`name             = "%s"
`, config.name)
	}

	// Test behavior whether disabled is specified or omitted (in which case it should default to false)
	if config.specifyDisabled {
		resource += fmt.Sprintf(`disabled             = %t
`, config.disabled)
	}

	if config.metadata != "" {
		resource += fmt.Sprintf(`metadata             = %s
`, config.metadata)
	}
	resource += `}`
	return resource
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
	return string(pemBytes)
	// return strings.TrimSuffix(string(pemBytes), "\n")
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
