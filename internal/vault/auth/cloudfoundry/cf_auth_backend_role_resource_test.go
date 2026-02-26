// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudfoundry_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccCFAuthBackendRole tests full CRUD lifecycle and import for
// the vault_cf_auth_backend_role resource.
func TestAccCFAuthBackendRole(t *testing.T) {
	mount := acctest.RandomWithPrefix("cf-mount")
	resourceAddress := "vault_cf_auth_backend_role.test"

	appIDs := []string{"2d3e834a-3a25-4591-974c-fa5626d5d0a1"}
	spaceIDs := []string{"3d2eba6b-ef19-44d5-91dd-1975b0db5cc9"}
	orgIDs := []string{"34a878d0-c2f9-4521-ba73-a9f664e82c7b"}
	instanceIDs := []string{"1bf2e7f6-2d1d-41ec-501c-c70"}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a minimal role with only mount and name.
			{
				Config: testAccCFAuthBackendRoleMinimal(mount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", "test-role"),
					resource.TestCheckNoResourceAttr(resourceAddress, "disable_ip_matching"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_application_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_space_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_organization_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_instance_ids.#", "0"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add all CF bound ID constraints.
			{
				Config: testAccCFAuthBackendRoleWithBoundIDs(mount, appIDs, spaceIDs, orgIDs, instanceIDs),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", "test-role"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_application_ids.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceAddress, "bound_application_ids.*", appIDs[0]),
					resource.TestCheckResourceAttr(resourceAddress, "bound_space_ids.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceAddress, "bound_space_ids.*", spaceIDs[0]),
					resource.TestCheckResourceAttr(resourceAddress, "bound_organization_ids.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceAddress, "bound_organization_ids.*", orgIDs[0]),
					resource.TestCheckResourceAttr(resourceAddress, "bound_instance_ids.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceAddress, "bound_instance_ids.*", instanceIDs[0]),
					resource.TestCheckNoResourceAttr(resourceAddress, "disable_ip_matching"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Set disable_ip_matching and expand bound application IDs.
			{
				Config: testAccCFAuthBackendRoleDisableIPMatching(mount,
					append(appIDs, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
					spaceIDs, orgIDs, instanceIDs,
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "disable_ip_matching", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_application_ids.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceAddress, "bound_application_ids.*", appIDs[0]),
					resource.TestCheckTypeSetElemAttr(resourceAddress, "bound_application_ids.*", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 4: Add all token fields.
			{
				Config: testAccCFAuthBackendRoleWithTokenFields(mount, appIDs, spaceIDs, orgIDs, instanceIDs),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", "test-role"),
					resource.TestCheckResourceAttr(resourceAddress, "disable_ip_matching", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "token_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceAddress, "token_max_ttl", "7200"),
					resource.TestCheckResourceAttr(resourceAddress, "token_policies.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceAddress, "token_policies.*", "policy-a"),
					resource.TestCheckTypeSetElemAttr(resourceAddress, "token_policies.*", "policy-b"),
					resource.TestCheckResourceAttr(resourceAddress, "token_bound_cidrs.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceAddress, "token_bound_cidrs.*", "10.0.0.0/8"),
					resource.TestCheckResourceAttr(resourceAddress, "token_explicit_max_ttl", "10800"),
					resource.TestCheckResourceAttr(resourceAddress, "token_no_default_policy", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "token_num_uses", "5"),
					resource.TestCheckResourceAttr(resourceAddress, "token_period", "600"),
					resource.TestCheckResourceAttr(resourceAddress, "token_type", "service"),
					resource.TestCheckResourceAttr(resourceAddress, "alias_metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "alias_metadata.org_id", "my-org"),
					resource.TestCheckResourceAttr(resourceAddress, "alias_metadata.space_id", "my-space"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 5: Clear token fields and bound IDs, revert to minimal.
			{
				Config: testAccCFAuthBackendRoleMinimal(mount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", "test-role"),
					resource.TestCheckNoResourceAttr(resourceAddress, "disable_ip_matching"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_application_ids.#", "0"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_ttl"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_max_ttl"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_policies.#"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_bound_cidrs.#"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_explicit_max_ttl"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_no_default_policy"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_num_uses"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_period"),
					resource.TestCheckResourceAttr(resourceAddress, "token_type", "default"),
					resource.TestCheckNoResourceAttr(resourceAddress, "alias_metadata.%"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 6: Import state.
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccCFAuthBackendRoleImportStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
			},
			// Step 7: Destroy the role (keep the mount).
			{
				Config: testAccCFAuthBackendConfigMountOnly(mount),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectNonEmptyPlan(),
						plancheck.ExpectResourceAction(resourceAddress, plancheck.ResourceActionDestroy),
					},
				},
			},
		},
	})
}

func testAccCFAuthBackendRoleImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("auth/%s/roles/%s",
			rs.Primary.Attributes["mount"],
			rs.Primary.Attributes["name"],
		), nil
	}
}

func testAccCFAuthBackendRoleMinimal(mount string) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_role" "test" {
  mount = vault_auth_backend.cf.path
  name  = "test-role"
}
`, testAccCFAuthBackendConfigMountOnly(mount))
}

func testAccCFAuthBackendRoleWithBoundIDs(mount string, appIDs, spaceIDs, orgIDs, instanceIDs []string) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_role" "test" {
  mount                  = vault_auth_backend.cf.path
  name                   = "test-role"
  bound_application_ids  = [%s]
  bound_space_ids        = [%s]
  bound_organization_ids = [%s]
  bound_instance_ids     = [%s]
}
`, testAccCFAuthBackendConfigMountOnly(mount),
		quoteList(appIDs), quoteList(spaceIDs), quoteList(orgIDs), quoteList(instanceIDs))
}

func testAccCFAuthBackendRoleDisableIPMatching(mount string, appIDs, spaceIDs, orgIDs, instanceIDs []string) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_role" "test" {
  mount                  = vault_auth_backend.cf.path
  name                   = "test-role"
  bound_application_ids  = [%s]
  bound_space_ids        = [%s]
  bound_organization_ids = [%s]
  bound_instance_ids     = [%s]
  disable_ip_matching    = true
}
`, testAccCFAuthBackendConfigMountOnly(mount),
		quoteList(appIDs), quoteList(spaceIDs), quoteList(orgIDs), quoteList(instanceIDs))
}

func testAccCFAuthBackendRoleWithTokenFields(mount string, appIDs, spaceIDs, orgIDs, instanceIDs []string) string {
	return fmt.Sprintf(`
%s

resource "vault_cf_auth_backend_role" "test" {
  mount                  = vault_auth_backend.cf.path
  name                   = "test-role"
  bound_application_ids  = [%s]
  bound_space_ids        = [%s]
  bound_organization_ids = [%s]
  bound_instance_ids     = [%s]
  disable_ip_matching    = true

  token_ttl               = 3600
  token_max_ttl           = 7200
  token_policies          = ["policy-a", "policy-b"]
  token_bound_cidrs       = ["10.0.0.0/8"]
  token_explicit_max_ttl  = 10800
  token_no_default_policy = true
  token_num_uses          = 5
  token_period            = 600
  token_type              = "service"
  alias_metadata          = { "org_id" = "my-org", "space_id" = "my-space" }
}
`, testAccCFAuthBackendConfigMountOnly(mount),
		quoteList(appIDs), quoteList(spaceIDs), quoteList(orgIDs), quoteList(instanceIDs))
}

// quoteList formats a []string as a comma-separated HCL list of quoted strings.
func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}

// TestAccCFAuthBackendRoleMultipleBoundIDs verifies that all four bound ID list
// fields accept and round-trip multiple elements correctly.
func TestAccCFAuthBackendRoleMultipleBoundIDs(t *testing.T) {
	mount := acctest.RandomWithPrefix("cf-mount")
	resourceAddress := "vault_cf_auth_backend_role.test"

	appIDs := []string{"2d3e834a-3a25-4591-974c-fa5626d5d0a1", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
	spaceIDs := []string{"3d2eba6b-ef19-44d5-91dd-1975b0db5cc9", "bbbbbbbb-1111-2222-3333-444444444444"}
	orgIDs := []string{"34a878d0-c2f9-4521-ba73-a9f664e82c7b", "cccccccc-5555-6666-7777-888888888888"}
	instanceIDs := []string{"1bf2e7f6-2d1d-41ec-501c-c70", "2ce3f8g7-3e4e-52fd-612d-d81"}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create role with 2 elements in every bound ID field.
			{
				Config: testAccCFAuthBackendRoleWithBoundIDs(mount, appIDs, spaceIDs, orgIDs, instanceIDs),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "bound_application_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_space_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_organization_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "bound_instance_ids.#", "2"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccCFAuthBackendRoleNamespace verifies that the role resource works correctly
// when deployed inside a Vault namespace (Enterprise only).
func TestAccCFAuthBackendRoleNamespace(t *testing.T) {
	mount := acctest.RandomWithPrefix("cf-mount")
	ns := acctest.RandomWithPrefix("ns")
	resourceAddress := "vault_cf_auth_backend_role.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the role inside a namespace.
			{
				Config: testAccCFAuthBackendRoleNamespace(ns, mount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceAddress, "mount", mount),
					resource.TestCheckResourceAttr(resourceAddress, "name", "test-role"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

func testAccCFAuthBackendRoleNamespace(ns, mount string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_auth_backend" "cf" {
  type      = "cf"
  path      = "%s"
  namespace = vault_namespace.test.path
}

resource "vault_cf_auth_backend_role" "test" {
  namespace = vault_namespace.test.path
  mount     = vault_auth_backend.cf.path
  name      = "test-role"
}
`, ns, mount)
}
