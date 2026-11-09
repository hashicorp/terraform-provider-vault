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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const maskingResourceAddress = "vault_transform_masking_transformation.test"

// TestAccTransformMaskingTransformation_basic validates the lifecycle of a masking transformation:
//   - Step 1: Create with only the required values; the omitted optional attributes must hold the expected default values in state with no drift
//   - Step 2: In-place update of masking_character and allowed_roles
//   - Step 3: Import state verification with the {mount}/{name} ID
//   - Step 4: Import state verification with the {mount}/transformation/{name} ID
func TestAccTransformMaskingTransformation_basic(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("masking")
	resourceAddress := maskingResourceAddress

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			// Step 1: Create with required values only
			{
				Config: testConfigMaskingTransformation(mount, name, builtinTemplate, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", name),
					resource.TestCheckResourceAttr(resourceAddress, "template", builtinTemplate),
					resource.TestCheckResourceAttr(resourceAddress, "masking_character", "*"),
					resource.TestCheckResourceAttr(resourceAddress, "allowed_roles.#", "0"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			// Step 2: In-place update of optional fields
			{
				Config: testConfigMaskingTransformation(mount, name, builtinTemplate, `
  masking_character = "#"
  allowed_roles     = ["role-a"]
`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", name),
					resource.TestCheckResourceAttr(resourceAddress, "template", builtinTemplate),
					resource.TestCheckResourceAttr(resourceAddress, "masking_character", "#"),
					resource.TestCheckResourceAttr(resourceAddress, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "allowed_roles.0", "role-a"),
				),
			},
			// Step 3: Shorthand import
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("%s/%s", mount, name),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
			// Step 4: Canonical import
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("%s/transformation/%s", mount, name),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

func TestAccTransformMaskingTransformation_validation(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("masking")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testConfigMaskingTransformation(mount, name, builtinTemplate, "  masking_character = \"xyz\"\n"),
				ExpectError: regexp.MustCompile(`Attribute masking_character string length must be between 1 and 1`),
			},
		},
	})
}

// TestAccTransformMaskingTransformation_terraformImport validates adopting a masking
// transformation that was created in Vault outside of Terraform:
//   - Step 1: terraform import (persisted)
//   - Step 2: the same config -> empty plan, the transformation is only adopted
//   - Step 3: optional fields set -> in-place update
func TestAccTransformMaskingTransformation_terraformImport(t *testing.T) {
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform-mount")
	name := acctest.RandomWithPrefix("masking")

	mountTransformWithWrappingKey(t, mount)
	cli := acctestutil.TestProvider.Meta().(*provider.ProviderMeta).MustGetClient()
	if _, err := cli.Logical().Write(fmt.Sprintf("%s/transformations/masking/%s", mount, name), map[string]any{
		"template": builtinTemplate,
	}); err != nil {
		t.Fatalf("failed to create masking transformation outside Terraform: %v", err)
	}

	adoptConfig := testConfigMaskingTransformationExistingMount(mount, name, builtinTemplate, "")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:             adoptConfig,
				ResourceName:       maskingResourceAddress,
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
					resource.TestCheckResourceAttr(maskingResourceAddress, "template", builtinTemplate),
					resource.TestCheckResourceAttr(maskingResourceAddress, "masking_character", "*"),
				),
			},
			{
				Config: testConfigMaskingTransformationExistingMount(mount, name, builtinTemplate, `
  masking_character = "#"
  allowed_roles     = ["role-a"]
`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(maskingResourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(maskingResourceAddress, "masking_character", "#"),
					resource.TestCheckResourceAttr(maskingResourceAddress, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(maskingResourceAddress, "allowed_roles.0", "role-a"),
				),
			},
		},
	})
}

// TestAccTransformMaskingTransformation_terraformImportWrongType validates that a transformation
// of another type cannot be imported into the masking resource.
func TestAccTransformMaskingTransformation_terraformImportWrongType(t *testing.T) {
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
				Config:        testConfigMaskingTransformationExistingMount(mount, name, builtinTemplate, ""),
				ResourceName:  maskingResourceAddress,
				ImportState:   true,
				ImportStateId: fmt.Sprintf("%s/%s", mount, name),
				ExpectError:   regexp.MustCompile(`Unexpected\s+transformation\s+type`),
			},
		},
	})
}

// testConfigMaskingTransformationExistingMount renders the resource config for a Transform mount
// that already exists outside of the config, referencing it by literal path.
func testConfigMaskingTransformationExistingMount(mount, name, template, extra string) string {
	return fmt.Sprintf(`
resource "vault_transform_masking_transformation" "test" {
  mount    = %q
  name     = %q
  template = %q
%s
}
`, mount, name, template, extra)
}

func testConfigMaskingTransformation(mount, name, template, extra string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "transform"
}

resource "vault_transform_masking_transformation" "test" {
  mount    = vault_mount.test.path
  name     = %q
  template = %q
%s
}
`, mount, name, template, extra)
}
