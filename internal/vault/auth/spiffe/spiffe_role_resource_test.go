// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package spiffe_test

import (
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

// TestAccSpiffeAuthRole tests the spiffe auth role resource
func TestAccSpiffeAuthRole(t *testing.T) {
	mount := acctest.RandomWithPrefix("spiffe-mount")
	resourceAddress := "vault_spiffe_auth_backend_role.spiffe_role"

	workloadIds := []string{"/+/test/*", "/example/*"}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test the simplest form of a role
			{
				Config: spiffeRoleConfig(mount, workloadIds),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceAddress, "mount"),
					resource.TestCheckResourceAttr(resourceAddress, "name", "example-role"),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.#", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.0", workloadIds[0]),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.1", workloadIds[1]),
				),
			},
			// Test updating the role to have a different workload id patterns (workload id can't be empty)
			{
				Config: spiffeRoleConfig(mount, []string{workloadIds[1]}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceAddress, "mount"),
					resource.TestCheckResourceAttr(resourceAddress, "name", "example-role"),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.0", workloadIds[1]),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_ttl"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_max_ttl"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_policies"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_bound_cidrs"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_explicit_max_ttl"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_no_default_policy"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_num_uses"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_period"),
					resource.TestCheckResourceAttr(resourceAddress, "token_type", "default"),
					resource.TestCheckNoResourceAttr(resourceAddress, "alias_metadata"),
				),
			},
			// Test updating all the token fields
			{
				Config: spiffeRoleWithTokenConfig(mount, []string{workloadIds[1]}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceAddress, "mount"),
					resource.TestCheckResourceAttr(resourceAddress, "name", "example-role"),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.0", workloadIds[1]),
					resource.TestCheckResourceAttr(resourceAddress, "token_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceAddress, "token_max_ttl", "7200"),
					resource.TestCheckResourceAttr(resourceAddress, "token_policies.#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "token_policies.0", "example"),
					resource.TestCheckResourceAttr(resourceAddress, "token_bound_cidrs.#", "1"),
					resource.TestCheckResourceAttr(resourceAddress, "token_bound_cidrs.0", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceAddress, "token_explicit_max_ttl", "10800"),
					resource.TestCheckResourceAttr(resourceAddress, "token_no_default_policy", "true"),
					resource.TestCheckResourceAttr(resourceAddress, "token_num_uses", "3"),
					resource.TestCheckResourceAttr(resourceAddress, "token_period", "60"),
					resource.TestCheckResourceAttr(resourceAddress, "token_type", "service"),
					resource.TestCheckResourceAttr(resourceAddress, "alias_metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "alias_metadata.spiffe_workload", "my-workload-id"),
					resource.TestCheckResourceAttr(resourceAddress, "alias_metadata.metadata-key", "metadata-value"),
				),
			},
			// Test that we flush back to a simpler role
			{
				Config: spiffeRoleConfig(mount, workloadIds),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceAddress, "mount"),
					resource.TestCheckResourceAttr(resourceAddress, "name", "example-role"),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.#", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.0", workloadIds[0]),
					resource.TestCheckResourceAttr(resourceAddress, "workload_id_patterns.1", workloadIds[1]),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_ttl"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_max_ttl"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_policies"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_bound_cidrs"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_explicit_max_ttl"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_no_default_policy"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_num_uses"),
					resource.TestCheckNoResourceAttr(resourceAddress, "token_period"),
					resource.TestCheckResourceAttr(resourceAddress, "token_type", "default"),
					resource.TestCheckNoResourceAttr(resourceAddress, "alias_metadata"),
				),
			},
			// Test importing
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccSpiffeAuthRoleImportStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
			},
			// Test deleting the role
			{
				Config: spiffeRoleConfigNoRole(mount),
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

func testAccSpiffeAuthRoleImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("auth/%s/role/%s", rs.Primary.Attributes["mount"], rs.Primary.Attributes["name"]), nil
	}
}

func spiffeRoleConfigNoRole(mount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "spiffe_mount" {
  type = "spiffe"
  path = "%s"

  tune {
    passthrough_request_headers = ["Authorization"]
  }
}
`, mount)
}

func spiffeRoleConfig(mount string, workloadIds []string) string {
	var formattedWorkload string
	if len(workloadIds) > 0 {
		formattedWorkload = "\"" + strings.Join(workloadIds, "\", \"") + "\""
	}

	baseMountTf := spiffeRoleConfigNoRole(mount)

	return fmt.Sprintf(`
%s

resource "vault_spiffe_auth_backend_role" "spiffe_role" {
  mount        = vault_auth_backend.spiffe_mount.path
  name         = "example-role"
  workload_id_patterns = [%s]
}
`, baseMountTf, formattedWorkload)
}

func spiffeRoleWithTokenConfig(mount string, workloadIds []string) string {
	var formattedWorkload string
	if len(workloadIds) > 0 {
		formattedWorkload = "\"" + strings.Join(workloadIds, "\", \"") + "\""
	}

	baseMountTf := spiffeRoleConfigNoRole(mount)

	return fmt.Sprintf(`
%s

resource "vault_spiffe_auth_backend_role" "spiffe_role" {
  mount        = vault_auth_backend.spiffe_mount.path
  name         = "example-role"
  workload_id_patterns = [%s]
  token_ttl = 3600
  token_max_ttl = 7200
  token_policies = ["example"]
  token_bound_cidrs = ["127.0.0.1"]
  token_explicit_max_ttl = 10800
  token_no_default_policy = true
  token_num_uses = 3
  token_period = 60
  token_type = "service"
  alias_metadata = { 
	"spiffe_workload" = "my-workload-id", 
    "metadata-key" = "metadata-value" 
  }
}
`, baseMountTf, formattedWorkload)
}
