// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package identity_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccIdentityTPMGroup validates the complete lifecycle of a TPM group resource:
// - Creation with minimal config (tests defaults: auto-generated name, empty member_tpm_ids)
// - Updating name field (verifies tpm_group_id remains unchanged as it's immutable)
// - Adding member TPM IDs
// - Import workflow (validates state reconstruction from Vault API)
// - Destruction
func TestAccIdentityTPMGroup(t *testing.T) {
	renamedName := acctest.RandomWithPrefix("tpm-group")
	resourceName := "vault_identity_tpm_group.test"
	tpmOnePublicKey := testTPMPublicKey(t)
	tpmTwoPublicKey := testTPMPublicKey(t)
	var originalTPMGroupID string

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create minimal config with no name or members to assert default behavior
			{
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "name"),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "0"),
					resource.TestCheckResourceAttrWith(resourceName, "tpm_group_id", func(value string) error {
						originalTPMGroupID = value
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
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					name:            renamedName,
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", renamedName),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "0"),
					resource.TestCheckResourceAttrWith(resourceName, "tpm_group_id", func(value string) error {
						if value != originalTPMGroupID {
							return fmt.Errorf("expected tpm_group_id %q after rename, got %q", originalTPMGroupID, value)
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
			// Step 3: Add member TPM IDs using resource references
			{
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					name:            renamedName,
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
					memberTPMIds:    "[vault_identity_tpm.one.tpm_id, vault_identity_tpm.two.tpm_id]",
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", renamedName),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "2"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "member_tpm_ids.*", "vault_identity_tpm.one", "tpm_id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "member_tpm_ids.*", "vault_identity_tpm.two", "tpm_id"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Import test validates an existing TPM group resource in Vault can be imported into Terraform state.
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccIdentityTPMGroupImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
			{
				Config: testAccIdentityTPMGroupConfigDestroyOnly(tpmOnePublicKey, tpmTwoPublicKey),
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

// TestAccIdentityTPMGroup_metadata verifies metadata field behavior:
// - Creating with metadata and verifying it's correctly imported from Vault
// - Omitting metadata clears it in Vault (config is the source of truth)
// - Re-adding metadata restores it
// - Setting metadata = {} explicitly clears it in Vault
func TestAccIdentityTPMGroup_metadata(t *testing.T) {
	resourceName := "vault_identity_tpm_group.test"
	groupName := acctest.RandomWithPrefix("tpm-group")
	tpmOnePublicKey := testTPMPublicKey(t)
	tpmTwoPublicKey := testTPMPublicKey(t)
	var tpmGroupID string

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with metadata
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					name:            groupName,
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
					metadata: `{
					environment = "test"
					team = "platform"
				}`,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_group_id", func(value string) error {
						tpmGroupID = value
						return nil
					}),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.environment", "test"),
					resource.TestCheckResourceAttr(resourceName, "metadata.team", "platform"),
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
				ImportStateIdFunc:                    testAccIdentityTPMGroupImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
			{
				// Step 3: Omitting metadata clears it in Vault
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					name:            groupName,
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_group_id", func(value string) error {
						if value != tpmGroupID {
							return fmt.Errorf("expected tpm_group_id to remain %q, got %q", tpmGroupID, value)
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
				// Step 4: Re-add metadata to test explicit clear below
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					name:            groupName,
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
					metadata: `{
					environment = "test"
					team = "platform"
				}`,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_group_id", func(value string) error {
						if value != tpmGroupID {
							return fmt.Errorf("expected tpm_group_id to remain %q, got %q", tpmGroupID, value)
						}
						return nil
					}),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.environment", "test"),
					resource.TestCheckResourceAttr(resourceName, "metadata.team", "platform"),
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
				// Step 5: Setting metadata = {} explicitly clears it in Vault
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					name:            groupName,
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
					metadata:        `{}`,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_group_id", func(value string) error {
						if value != tpmGroupID {
							return fmt.Errorf("expected tpm_group_id to remain %q, got %q", tpmGroupID, value)
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

// TestAccIdentityTPMGroup_memberTPMIds verifies member_tpm_ids field behavior:
// - Creating with member TPM IDs and verifying they're correctly imported from Vault
// - Removing one member updates Vault
// - Omitting member_tpm_ids clears members in Vault (config is the source of truth)
func TestAccIdentityTPMGroup_memberTPMIds(t *testing.T) {
	resourceName := "vault_identity_tpm_group.test"
	groupName := acctest.RandomWithPrefix("tpm-group")
	tpmOnePublicKey := testTPMPublicKey(t)
	tpmTwoPublicKey := testTPMPublicKey(t)
	var tpmGroupID string

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with member TPM IDs
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					name:            groupName,
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
					memberTPMIds:    "[vault_identity_tpm.one.tpm_id, vault_identity_tpm.two.tpm_id]",
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_group_id", func(value string) error {
						tpmGroupID = value
						return nil
					}),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "2"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "member_tpm_ids.*", "vault_identity_tpm.one", "tpm_id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "member_tpm_ids.*", "vault_identity_tpm.two", "tpm_id"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				// Step 2: Import to verify member_tpm_ids round-trips correctly from Vault
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccIdentityTPMGroupImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
			{
				// Step 3: Remove one member
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					name:            groupName,
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
					memberTPMIds:    "[vault_identity_tpm.one.tpm_id]",
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_group_id", func(value string) error {
						if value != tpmGroupID {
							return fmt.Errorf("expected tpm_group_id to remain %q, got %q", tpmGroupID, value)
						}
						return nil
					}),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "member_tpm_ids.*", "vault_identity_tpm.one", "tpm_id"),
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
				// Step 4: Omitting member_tpm_ids clears all members in Vault
				Config: testAccIdentityTPMGroupConfig(tpmGroupConfigFields{
					name:            groupName,
					tpmOnePublicKey: tpmOnePublicKey,
					tpmTwoPublicKey: tpmTwoPublicKey,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "tpm_group_id", func(value string) error {
						if value != tpmGroupID {
							return fmt.Errorf("expected tpm_group_id to remain %q, got %q", tpmGroupID, value)
						}
						return nil
					}),
					resource.TestCheckResourceAttr(resourceName, "member_tpm_ids.#", "0"),
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

type tpmGroupConfigFields struct {
	name            string
	tpmOnePublicKey string
	tpmTwoPublicKey string
	memberTPMIds    string
	metadata        string
}

func testAccIdentityTPMGroupConfig(config tpmGroupConfigFields) string {
	tpmResources := fmt.Sprintf(`
resource "vault_identity_tpm" "one" {
  tpm_ek_public_key = <<EOT
%s
EOT
}

resource "vault_identity_tpm" "two" {
  tpm_ek_public_key = <<EOT
%s
EOT
}

`, config.tpmOnePublicKey, config.tpmTwoPublicKey)

	groupResource := `resource "vault_identity_tpm_group" "test" {
`

	if config.name != "" {
		groupResource += fmt.Sprintf(`  name = "%s"
`, config.name)
	}

	if config.memberTPMIds != "" {
		groupResource += fmt.Sprintf(`  member_tpm_ids = %s
`, config.memberTPMIds)
	}

	if config.metadata != "" {
		groupResource += fmt.Sprintf(`  metadata = %s
`, config.metadata)
	}

	groupResource += `}`

	return tpmResources + groupResource
}

func testAccIdentityTPMGroupConfigDestroyOnly(tpmOnePublicKey, tpmTwoPublicKey string) string {
	return fmt.Sprintf(`
resource "vault_identity_tpm" "one" {
  tpm_ek_public_key = <<EOT
%s
EOT
}

resource "vault_identity_tpm" "two" {
  tpm_ek_public_key = <<EOT
%s
EOT
}
`, tpmOnePublicKey, tpmTwoPublicKey)
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
