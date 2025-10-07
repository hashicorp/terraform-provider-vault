package spiffe_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccSpiffeAuthRole(t *testing.T) {
	testutil.SkipTestAccEnt(t)
	mount := acctest.RandomWithPrefix("spiffe-mount")
	resourceAddress := "vault_spiffe_auth_role.spiffe_role"

	workloadIds := []string{"/+/test/*", "/example/*"}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			// FIXME: Add a Test for Vault 1.21.x
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

resource "vault_spiffe_auth_role" "spiffe_role" {
  mount        = vault_auth_backend.spiffe_mount.path
  name         = "example-role"
  workload_id_patterns = [%s]
}
`, baseMountTf, formattedWorkload)
}
