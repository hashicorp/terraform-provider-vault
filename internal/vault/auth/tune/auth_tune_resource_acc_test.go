// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tune_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccAuthTune(t *testing.T) {
	path := acctest.RandomWithPrefix("auth-tune")
	resourceName := "vault_auth_tune.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAuthTuneConfig(path, "200s", "batch", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl", "200s"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "batch"),
					resource.TestCheckNoResourceAttr(resourceName, "max_lease_ttl"),
					resource.TestCheckNoResourceAttr(resourceName, "listing_visibility"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccAuthTuneConfig(path, "10m", "", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl", "20m"),
					resource.TestCheckNoResourceAttr(resourceName, "token_type"),
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
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateIdFunc:       testAccAuthTuneImportID(resourceName),
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"default_lease_ttl", "max_lease_ttl"},
			},
		},
	})
}

func testAccAuthTuneImportID(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return rs.Primary.Attributes["path"], nil
	}
}

func testAccAuthTuneConfig(path, defaultTTL, tokenType string, withMax bool) string {
	body := fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "userpass"
  path = %q
}

resource "vault_auth_tune" "test" {
  path              = vault_auth_backend.test.path
  default_lease_ttl = %q
`, path, defaultTTL)
	if tokenType != "" {
		body += fmt.Sprintf("  token_type        = %q\n", tokenType)
	}
	if withMax {
		body += "  max_lease_ttl     = \"20m\"\n"
	}
	body += "}\n"
	return body
}
