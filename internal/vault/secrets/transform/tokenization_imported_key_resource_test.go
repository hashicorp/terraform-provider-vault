// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const tokenizationResourceAddress = "vault_transform_transformation_tokenization_imported_key.test"

// TestAccTransformTokenizationImportedKey_basic validates the lifecycle of a tokenization transformation:
//   - Step 1: Create with an imported key and only the required values; the omitted optional attributes must hold the expected default values in state with no drift
//   - Step 2: In-place update of tunables and deletion_allowed; the ciphertext is not re-sent, so latest_version stays 1
//   - Step 3: A bumped ciphertext_wo_version imports a new key version
//   - Step 4: Key settings (min_decryption_version) are updated in place
//   - Step 5: Key material removed from config -> in-place update that imports nothing
//   - Step 6: Changing allow_rotation replaces the transformation, since Vault only applies it on import
//   - Step 7: Import state verification
func TestAccTransformTokenizationImportedKey_basic(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("transform-tf")

	wrappingKey := mountTransformWithWrappingKey(t, mount)
	ciphertext1 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")
	ciphertext2 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with only the required values. This checks that the provider leaves
			// the default values returned for the omitted optional attributes intact in state
			// and plans no diff afterwards. It does not test Vault's behavior.
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:               mount,
					name:                name,
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "name", name),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "mapping_mode", "default"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "max_ttl", "0"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "deletion_allowed", "false"),
					// Vault does not return allow_rotation and it is not computed, so it stays null when unset.
					resource.TestCheckNoResourceAttr(tokenizationResourceAddress, "allow_rotation"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "1"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "min_decryption_version", "1"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "auto_rotate_period", "0"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			// Step 3: ciphertext_wo stays in config but only tunables change, including enabling
			// deletion_allowed. ciphertext_wo_version is unchanged, so the ciphertext must not be
			// re-sent; latest_version staying at 1 proves it.
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:               mount,
					name:                name,
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
					deletionAllowed:     true,
					maxTTL:              int64Ptr(3600),
					allowedRoles:        `["role-a", "role-b"]`,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(tokenizationResourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "max_ttl", "3600"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "allowed_roles.0", "role-a"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "1"),
				),
			},
			// Step 4: New ciphertext with a bumped ciphertext_wo_version -> in-place update that
			// imports the ciphertext as version 2.
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:               mount,
					name:                name,
					ciphertext:          ciphertext2,
					ciphertextWOVersion: 2,
					deletionAllowed:     true,
					maxTTL:              int64Ptr(3600),
					allowedRoles:        `["role-a", "role-b"]`,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(tokenizationResourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "2"),
			},
			// Step 5: Key settings are updated through the key config endpoint.
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:                mount,
					name:                 name,
					ciphertext:           ciphertext2,
					ciphertextWOVersion:  2,
					deletionAllowed:      true,
					maxTTL:               int64Ptr(3600),
					allowedRoles:         `["role-a", "role-b"]`,
					minDecryptionVersion: 2,
					autoRotatePeriod:     int64Ptr(7200),
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(tokenizationResourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "min_decryption_version", "2"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "auto_rotate_period", "7200"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "2"),
				),
			},
			// Step 6: ciphertext_wo and ciphertext_wo_version removed from config. The only change is
			// clearing ciphertext_wo_version in state: an in-place update that imports no new version.
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:                mount,
					name:                 name,
					deletionAllowed:      true,
					maxTTL:               int64Ptr(3600),
					allowedRoles:         `["role-a", "role-b"]`,
					minDecryptionVersion: 2,
					autoRotatePeriod:     int64Ptr(7200),
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(tokenizationResourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "2"),
			},
			// Step 7: Vault only applies allow_rotation on import, so changing it replaces the
			// transformation. The new transformation is imported from ciphertext1, so latest_version
			// is back to 1.
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:               mount,
					name:                name,
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
					allowRotation:       true,
					deletionAllowed:     true,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(tokenizationResourceAddress, plancheck.ResourceActionDestroyBeforeCreate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "allow_rotation", "true"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "1"),
				),
			},
			// Step 8: Import state verification.
			{
				ResourceName:                         tokenizationResourceAddress,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("%s/%s", mount, name),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldCiphertextWO,
					consts.FieldCiphertextWOVersion,
					consts.FieldHashFunction,
					consts.FieldAllowRotation,
				},
			},
		},
	})
}

// TestAccTransformTokenizationImportedKey_hashFunction validates importing ciphertext wrapped with a
// non-default RSA-OAEP hash function, both on create and when importing a new key version.
func TestAccTransformTokenizationImportedKey_hashFunction(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("transform-tf")

	wrappingKey := mountTransformWithWrappingKey(t, mount)
	ciphertext1 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA512")
	ciphertext2 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA384")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:               mount,
					name:                name,
					deletionAllowed:     true,
					ciphertext:          ciphertext1,
					ciphertextWOVersion: 1,
					hashFunction:        "SHA512",
				}),
				Check: resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "1"),
			},
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:               mount,
					name:                name,
					deletionAllowed:     true,
					ciphertext:          ciphertext2,
					ciphertextWOVersion: 2,
					hashFunction:        "SHA384",
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(tokenizationResourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "2"),
			},
		},
	})
}

// TestAccTransformTokenizationImportedKey_optionalFields validates setting the optional import arguments at
// create and reading them back.
func TestAccTransformTokenizationImportedKey_optionalFields(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("transform-tf")

	wrappingKey := mountTransformWithWrappingKey(t, mount)
	ciphertext := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with all optional fields set to non-default values.
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:                mount,
					name:                 name,
					ciphertext:           ciphertext,
					ciphertextWOVersion:  1,
					hashFunction:         "SHA256",
					allowRotation:        true,
					deletionAllowed:      true,
					allowedRoles:         `["role-a"]`,
					mappingMode:          "exportable",
					maxTTL:               int64Ptr(7200),
					stores:               `["builtin/internal"]`,
					minDecryptionVersion: 1,
					autoRotatePeriod:     int64Ptr(3600),
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "allow_rotation", "true"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "auto_rotate_period", "3600"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "mapping_mode", "exportable"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "max_ttl", "7200"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "stores.#", "1"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "stores.0", "builtin/internal"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "allowed_roles.0", "role-a"),
					resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestAccTransformTokenizationImportedKey_terraformImport validates adopting a tokenization
// transformation that was imported into Vault outside of Terraform:
//   - Step 1: terraform import (persisted), no key material in config
//   - Step 2: config without key material -> empty plan, the transformation is only adopted
//   - Step 3: ciphertext_wo with a version -> a new key version is imported in place
func TestAccTransformTokenizationImportedKey_terraformImport(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("transform-tf")

	wrappingKey := mountTransformWithWrappingKey(t, mount)
	ciphertext1 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")
	ciphertext2 := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")

	importTransformationVaultSetup(t, mount, "tokenization", name, map[string]any{
		"ciphertext": ciphertext1,
	})

	adoptFields := importedKeyFields{
		mount:           mount,
		name:            name,
		deletionAllowed: true,
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:             importedKeyConfig("tokenization", adoptFields),
				ResourceName:       tokenizationResourceAddress,
				ImportState:        true,
				ImportStateId:      fmt.Sprintf("%s/%s", mount, name),
				ImportStatePersist: true,
			},
			{
				Config: importedKeyConfig("tokenization", adoptFields),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "1"),
			},
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount:               mount,
					name:                name,
					deletionAllowed:     true,
					ciphertext:          ciphertext2,
					ciphertextWOVersion: 1,
				}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(tokenizationResourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(tokenizationResourceAddress, "latest_version", "2"),
			},
		},
	})
}

// TestAccTransformTokenizationImportedKey_terraformImportWrongType validates that a transformation cannot be
// imported into the resource for the other transformation type.
func TestAccTransformTokenizationImportedKey_terraformImportWrongType(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("transform-fpe")

	wrappingKey := mountTransformWithWrappingKey(t, mount)
	importTransformationVaultSetup(t, mount, "fpe", name, map[string]any{
		"ciphertext": testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256"),
		"template":   builtinTemplate,
	})

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: importedKeyConfig("tokenization", importedKeyFields{
					mount: mount,
					name:  name,
				}),
				ResourceName:  tokenizationResourceAddress,
				ImportState:   true,
				ImportStateId: fmt.Sprintf("%s/%s", mount, name),
				ExpectError:   regexp.MustCompile(`Unexpected\s+transformation\s+type`),
			},
		},
	})
}

// TestAccTransformTokenizationImportedKey_createFailureAfterImportIsTracked validates that a transformation
// whose /import succeeded is still saved to state when a later step of Create fails, instead of
// being orphaned in Vault:
//   - Step 1: auto_rotate_period below Vault's minimum fails the key config write after /import
//   - Step 2: a valid config replaces the tainted resource, which only happens if step 1 saved it
func TestAccTransformTokenizationImportedKey_createFailureAfterImportIsTracked(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("transform-tf")

	wrappingKey := mountTransformWithWrappingKey(t, mount)
	ciphertext := testutil.CreateBYOKCiphertext(t, wrappingKey, testutil.RandomAESKey(t), "SHA256")

	config := func(autoRotatePeriod int64) string {
		return importedKeyConfig("tokenization", importedKeyFields{
			mount:               mount,
			name:                name,
			ciphertext:          ciphertext,
			ciphertextWOVersion: 1,
			deletionAllowed:     true,
			autoRotatePeriod:    &autoRotatePeriod,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      config(60),
				ExpectError: regexp.MustCompile(`Unable to Create Resource`),
			},
			{
				Config: config(3600),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(tokenizationResourceAddress, plancheck.ResourceActionDestroyBeforeCreate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(tokenizationResourceAddress, "auto_rotate_period", "3600"),
			},
		},
	})
}
