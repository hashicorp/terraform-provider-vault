// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

const fpeResourceAddress = "vault_transform_transformation_fpe.test"

// Built-in Vault Transform templates, so the tests do not need to create their own.
const (
	templateCreditCard = "builtin/creditcardnumber"
	templateSSN        = "builtin/socialsecuritynumber"
)

// TestAccTransformationFPE_basic validates the lifecycle with Vault defaults:
//   - Step 1: Create with required fields only. Vault defaults tweak_source to "supplied".
//   - Step 2: In-place update of template, tweak_source and allowed_roles.
//   - Step 3: Import state verification.
func TestAccTransformationFPE_basic(t *testing.T) {
	// checkFPEVersionGatedAttrs inspects the provider's Vault version while the TestCase
	// is built, so the provider must already be configured.
	acctestutil.TestEntPreCheck(t)

	mount := acctest.RandomWithPrefix("transform")
	name := acctest.RandomWithPrefix("fpe")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccTransformationFPECheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: fpeConfig(fpeFields{mount: mount, name: name, template: templateCreditCard}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldName, name),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldTemplate, templateCreditCard),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldTweakSource, "supplied"),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckNoResourceAttr(fpeResourceAddress, consts.FieldAllowedRoles+".#"),
					checkFPEVersionGatedAttrs(fpeResourceAddress),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: fpeConfig(fpeFields{
					mount:        mount,
					name:         name,
					template:     templateSSN,
					tweakSource:  "internal",
					allowedRoles: []string{"payments"},
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldTemplate, templateSSN),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldTweakSource, "internal"),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldAllowedRoles+".#", "1"),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldAllowedRoles+".0", "payments"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(fpeResourceAddress, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				ResourceName:                         fpeResourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTransformationFPEImportStateIDFunc(fpeResourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

// TestAccTransformationFPE_optionalFields validates that optional fields can be added and
// removed again:
//   - Step 1: Create with allowed_roles and tweak_source set
//   - Step 2: Remove allowed_roles -> Vault clears the roles and the attribute returns to null
//   - Step 3: Add allowed_roles back with multiple roles
func TestAccTransformationFPE_optionalFields(t *testing.T) {
	mount := acctest.RandomWithPrefix("transform")
	name := acctest.RandomWithPrefix("fpe")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccTransformationFPECheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: fpeConfig(fpeFields{
					mount:        mount,
					name:         name,
					template:     templateCreditCard,
					tweakSource:  "generated",
					allowedRoles: []string{"payments"},
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldTweakSource, "generated"),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldAllowedRoles+".#", "1"),
				),
			},
			{
				Config: fpeConfig(fpeFields{
					mount:       mount,
					name:        name,
					template:    templateCreditCard,
					tweakSource: "generated",
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(fpeResourceAddress, consts.FieldAllowedRoles+".#"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: fpeConfig(fpeFields{
					mount:        mount,
					name:         name,
					template:     templateCreditCard,
					tweakSource:  "generated",
					allowedRoles: []string{"payments", "billing"},
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldAllowedRoles+".#", "2"),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldAllowedRoles+".0", "payments"),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldAllowedRoles+".1", "billing"),
				),
			},
		},
	})
}

// TestAccTransformationFPE_maxTweakLen validates max_tweak_len and fpe_algorithm, which Vault
// returns as of 2.2.0 (new transformations use FF1):
//   - Step 1: Create with max_tweak_len = 8, verify both fields are populated
//   - Step 2: Import state verification
func TestAccTransformationFPE_maxTweakLen(t *testing.T) {
	mount := acctest.RandomWithPrefix("transform")
	name := acctest.RandomWithPrefix("fpe")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccTransformationFPECheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: fpeConfig(fpeFields{
					mount:       mount,
					name:        name,
					template:    templateCreditCard,
					tweakSource: "supplied",
					maxTweakLen: int64Ptr(8),
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldMaxTweakLen, "8"),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldFpeAlgorithm, "ff1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				ResourceName:                         fpeResourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTransformationFPEImportStateIDFunc(fpeResourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

// TestAccTransformationFPE_deletionProtection validates the deletion_allowed default and the
// protection it gives. Deleting an FPE transformation destroys its encryption key, so Vault
// refuses to do it unless deletion_allowed is true:
//   - Step 1: Create without deletion_allowed -> reads back as false
//   - Step 2: Destroy is rejected by Vault and the transformation stays in state
//   - Step 3: Enable deletion_allowed in place so the test can clean up
func TestAccTransformationFPE_deletionProtection(t *testing.T) {
	mount := acctest.RandomWithPrefix("transform")
	name := acctest.RandomWithPrefix("fpe")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccTransformationFPECheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: fpeConfig(fpeFields{mount: mount, name: name, template: templateCreditCard, omitDeletionAllowed: true}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldDeletionAllowed, "false"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config:      fpeConfig(fpeFields{mount: mount, name: name, template: templateCreditCard, omitDeletionAllowed: true}),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`deletion_allowed is false`),
			},
			{
				Config: fpeConfig(fpeFields{mount: mount, name: name, template: templateCreditCard}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldDeletionAllowed, "true"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(fpeResourceAddress, plancheck.ResourceActionUpdate),
					},
				},
			},
		},
	})
}

// TestAccTransformationFPE_remount validates that changing mount replaces the resource.
func TestAccTransformationFPE_remount(t *testing.T) {
	mountA := acctest.RandomWithPrefix("transform-a")
	mountB := acctest.RandomWithPrefix("transform-b")
	name := acctest.RandomWithPrefix("fpe")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccTransformationFPECheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: fpeRemountConfig(mountA, mountB, name, "a"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldMount, mountA),
				),
			},
			{
				Config: fpeRemountConfig(mountA, mountB, name, "b"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(fpeResourceAddress, plancheck.ResourceActionReplace),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldMount, mountB),
				),
			},
		},
	})
}

// TestAccTransformationFPE_vaultManagedImport validates adopting an FPE transformation that was
// created directly in Vault (outside of Terraform):
//   - Step 1: Import the pre-existing transformation into Terraform state
//   - Step 2: Apply the config and expect an empty plan — verifies that all computed fields
//     (tweak_source, deletion_allowed, max_tweak_len, fpe_algorithm) are correctly populated
//     when only mount and name are present in state at import time.
func TestAccTransformationFPE_vaultManagedImport(t *testing.T) {
	mount := acctest.RandomWithPrefix("transform")
	name := acctest.RandomWithPrefix("fpe")

	// Create the transform mount and FPE transformation directly in Vault before any
	// Terraform steps run.
	acctestutil.TestEntPreCheck(t)
	cli := acctestutil.TestProvider.Meta().(*provider.ProviderMeta).MustGetClient()

	if _, err := cli.Logical().Write("sys/mounts/"+mount, map[string]any{"type": "transform"}); err != nil {
		t.Fatalf("failed to mount transform engine at %q: %s", mount, err)
	}
	t.Cleanup(func() {
		cli.Logical().Delete("sys/mounts/" + mount) //nolint:errcheck
	})
	if _, err := cli.Logical().Write(
		fmt.Sprintf("%s/transformations/fpe/%s", mount, name),
		map[string]any{
			"template":         templateCreditCard,
			"tweak_source":     "supplied",
			"deletion_allowed": true,
		},
	); err != nil {
		t.Fatalf("failed to create FPE transformation %q in Vault: %s", name, err)
	}

	// Use a config without a vault_mount resource — the mount was created directly in Vault
	// and is not managed by Terraform. fpeConfig would include vault_mount.test which would
	// appear as unmanaged after the import step and trigger a spurious create in step 2.
	adoptConfig := fmt.Sprintf(`
resource "vault_transform_transformation_fpe" "test" {
	 mount            = %q
	 name             = %q
	 template         = %q
	 deletion_allowed = true
}
`, mount, name, templateCreditCard)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccTransformationFPECheckDestroy,
		Steps: []resource.TestStep{
			// Step 1: Import the Vault-created transformation into Terraform state.
			{
				Config:             adoptConfig,
				ResourceName:       fpeResourceAddress,
				ImportState:        true,
				ImportStateId:      fmt.Sprintf("%s/%s", mount, name),
				ImportStatePersist: true,
			},
			// Step 2: Apply the same config and expect an empty plan. This confirms that
			// readFromVault correctly handles the null-vs-unknown state for computed fields
			// when only mount and name were present at import time.
			{
				Config: adoptConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldTemplate, templateCreditCard),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldTweakSource, "supplied"),
					resource.TestCheckResourceAttr(fpeResourceAddress, consts.FieldDeletionAllowed, "true"),
					checkFPEVersionGatedAttrs(fpeResourceAddress),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// fpeFields describes the optional settings rendered into the test config. Zero values are
// omitted so that Vault defaults apply.
type fpeFields struct {
	mount        string
	name         string
	template     string
	tweakSource  string
	allowedRoles []string
	maxTweakLen  *int64
	// omitDeletionAllowed leaves deletion_allowed out of the config so the default applies.
	omitDeletionAllowed bool
}

// fpeConfig renders a transform mount and an FPE transformation. deletion_allowed is true
// unless omitDeletionAllowed is set, so that the transformation can be destroyed at the end of each test.
func fpeConfig(f fpeFields) string {
	var optional strings.Builder
	if !f.omitDeletionAllowed {
		optional.WriteString("  deletion_allowed = true\n")
	}
	if f.tweakSource != "" {
		fmt.Fprintf(&optional, "  tweak_source     = %q\n", f.tweakSource)
	}
	if len(f.allowedRoles) > 0 {
		quoted := make([]string, len(f.allowedRoles))
		for i, r := range f.allowedRoles {
			quoted[i] = fmt.Sprintf("%q", r)
		}
		fmt.Fprintf(&optional, "  allowed_roles    = [%s]\n", strings.Join(quoted, ", "))
	}
	if f.maxTweakLen != nil {
		fmt.Fprintf(&optional, "  max_tweak_len    = %d\n", *f.maxTweakLen)
	}

	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "transform"
}

resource "vault_transform_transformation_fpe" "test" {
  mount            = vault_mount.test.path
  name             = %q
  template         = %q
%s}
`, f.mount, f.name, f.template, optional.String())
}

// fpeRemountConfig declares two transform mounts and points the transformation at one of them.
func fpeRemountConfig(mountA, mountB, name, use string) string {
	return fmt.Sprintf(`
resource "vault_mount" "a" {
  path = %q
  type = "transform"
}

resource "vault_mount" "b" {
  path = %q
  type = "transform"
}

resource "vault_transform_transformation_fpe" "test" {
  mount            = vault_mount.%s.path
  name             = %q
  template         = %q
  deletion_allowed = true
}
`, mountA, mountB, use, name, templateCreditCard)
}

// testAccTransformationFPEImportStateIDFunc builds the {mount}/{name} import ID. The resource
// has no id attribute, so the import ID must be supplied explicitly.
func testAccTransformationFPEImportStateIDFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("%s/%s", rs.Primary.Attributes[consts.FieldMount], rs.Primary.Attributes[consts.FieldName]), nil
	}
}

// testAccTransformationFPECheckDestroy verifies that every FPE transformation was deleted from Vault.
func testAccTransformationFPECheckDestroy(s *terraform.State) error {
	cli := acctestutil.TestProvider.Meta().(*provider.ProviderMeta).MustGetClient()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_transformation_fpe" {
			continue
		}
		p := fmt.Sprintf("%s/transformation/%s",
			strings.Trim(rs.Primary.Attributes[consts.FieldMount], "/"),
			rs.Primary.Attributes[consts.FieldName])
		secret, err := cli.Logical().Read(p)
		if err != nil {
			// The mount itself is destroyed with the test, which surfaces as a read error.
			continue
		}
		if secret != nil {
			return fmt.Errorf("FPE transformation %q still exists", p)
		}
	}
	return nil
}
