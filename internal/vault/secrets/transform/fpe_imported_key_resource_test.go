// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const fpeResourceAddress = "vault_transform_transformation_fpe_imported_key.test"

// TestAccTransformFPEImportedKey_basic validates the lifecycle of an FPE transformation:
//   - Step 1: Create with an imported key and only the required values
//   - Step 2: In-place update of deletion_allowed, allowed_roles and tweak_source
//   - Step 3: Bumping ciphertext_wo_version replaces the transformation, since Vault cannot import FPE key versions
//   - Step 4: Import state verification
func TestAccTransformFPEImportedKey_basic(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("transform-fpe")

	wrappingKey := mountTransformWithWrappingKey(t, mount)
	ciphertext1 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")
	ciphertext2 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with only the required values. This checks that the provider leaves
			// the default values returned for the omitted optional attributes intact in state
			// and plans no diff afterwards.
			{
				Config: importedKeyConfig("fpe", importedKeyFields{
					mount:               mount,
					name:                name,
					template:            builtinTemplate,
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, "template", builtinTemplate),
					resource.TestCheckResourceAttr(fpeResourceAddress, "tweak_source", "supplied"),
					resource.TestCheckResourceAttr(fpeResourceAddress, "max_tweak_len", "0"),
					resource.TestCheckResourceAttr(fpeResourceAddress, "deletion_allowed", "false"),
					resource.TestCheckResourceAttr(fpeResourceAddress, "fpe_algorithm", "ff1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			// Step 2: In-place update of settings Vault allows to change.
			{
				Config: importedKeyConfig("fpe", importedKeyFields{
					mount:               mount,
					name:                name,
					template:            builtinTemplate,
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
					tweakSource:         "internal",
					deletionAllowed:     true,
					allowedRoles:        `["role-a"]`,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(fpeResourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, "tweak_source", "internal"),
					resource.TestCheckResourceAttr(fpeResourceAddress, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(fpeResourceAddress, "allowed_roles.#", "1"),
				),
			},
			// Step 3: Vault has no import_version endpoint for FPE, so a new version replaces the
			// transformation with one created from the new ciphertext.
			{
				Config: importedKeyConfig("fpe", importedKeyFields{
					mount:               mount,
					name:                name,
					template:            builtinTemplate,
					ciphertext:          ciphertext2,
					ciphertextWOVersion: 2,
					tweakSource:         "internal",
					deletionAllowed:     true,
					allowedRoles:        `["role-a"]`,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(fpeResourceAddress, plancheck.ResourceActionDestroyBeforeCreate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(fpeResourceAddress, "ciphertext_wo_version", "2"),
			},
			// Step 4: Import state verification.
			{
				ResourceName:                         fpeResourceAddress,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("%s/%s", mount, name),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertextWO,
					consts.FieldCiphertextWOVersion,
					consts.FieldHashFunction,
				},
			},
		},
	})
}

// TestAccTransformFPEImportedKey_ciphertextWOVersionReplace validates when ciphertext_wo_version
// replaces an FPE transformation. Vault cannot import a key into an existing FPE transformation,
// so setting the version replaces it, while removing the version does not:
//   - Step 1: Create with version 1
//   - Step 2: Remove the version -> in-place update
//   - Step 3: Set the version again -> replaced, created from the new ciphertext
func TestAccTransformFPEImportedKey_ciphertextWOVersionReplace(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("transform-fpe")
	wrappingKey := mountTransformWithWrappingKey(t, mount)
	ciphertext1 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")
	ciphertext2 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")

	// An FPE transformation exposes no key version, so the PreApply PlanCheck is what we're asserting in each step.
	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with version 1 -> ResourceActionCreate
			{
				Config: importedKeyConfig("fpe", importedKeyFields{
					mount:               mount,
					name:                name,
					template:            builtinTemplate,
					tweakSource:         "internal",
					deletionAllowed:     true,
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             []plancheck.PlanCheck{plancheck.ExpectResourceAction(fpeResourceAddress, plancheck.ResourceActionCreate)},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(fpeResourceAddress, "ciphertext_wo_version", "1"),
			},
			// Step 2: Remove the version -> In-place update
			{
				Config: importedKeyConfig("fpe", importedKeyFields{
					mount:           mount,
					name:            name,
					template:        builtinTemplate,
					tweakSource:     "internal",
					deletionAllowed: true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             []plancheck.PlanCheck{plancheck.ExpectResourceAction(fpeResourceAddress, plancheck.ResourceActionUpdate)},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckNoResourceAttr(fpeResourceAddress, "ciphertext_wo_version"),
			},
			// Step 3: Set the version again -> DestroyBeforeCreate replacement
			{
				Config: importedKeyConfig("fpe", importedKeyFields{
					mount:               mount,
					name:                name,
					template:            builtinTemplate,
					tweakSource:         "internal",
					deletionAllowed:     true,
					ciphertext:          ciphertext2,
					ciphertextWOVersion: 3,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             []plancheck.PlanCheck{plancheck.ExpectResourceAction(fpeResourceAddress, plancheck.ResourceActionDestroyBeforeCreate)},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(fpeResourceAddress, "ciphertext_wo_version", "3"),
			},
		},
	})
}

// TestAccTransformFPEImportedKey_terraformImport validates adopting an FPE transformation that was
// imported into Vault outside of Terraform.
func TestAccTransformFPEImportedKey_terraformImport(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("transform-fpe")
	wrappingKey := mountTransformWithWrappingKey(t, mount)
	ciphertext := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")

	importTransformationVaultSetup(t, mount, "fpe", name, map[string]any{
		"ciphertext":   ciphertext,
		"template":     builtinTemplate,
		"tweak_source": "supplied",
	})

	adoptConfig := importedKeyConfig("fpe", importedKeyFields{
		mount:           mount,
		name:            name,
		template:        builtinTemplate,
		tweakSource:     "supplied",
		deletionAllowed: true,
	})

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:             adoptConfig,
				ResourceName:       fpeResourceAddress,
				ImportState:        true,
				ImportStateId:      fmt.Sprintf("%s/%s", mount, name),
				ImportStatePersist: true,
			},
			{
				Config: adoptConfig,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, "template", builtinTemplate),
				),
			},
			// Setting the version on an adopted transformation replaces it, created from the
			// ciphertext.
			{
				Config: importedKeyConfig("fpe", importedKeyFields{
					mount:               mount,
					name:                name,
					template:            builtinTemplate,
					tweakSource:         "supplied",
					deletionAllowed:     true,
					ciphertext:          ciphertext,
					ciphertextWOVersion: 1,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(fpeResourceAddress, plancheck.ResourceActionDestroyBeforeCreate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(fpeResourceAddress, "ciphertext_wo_version", "1"),
			},
		},
	})
}
