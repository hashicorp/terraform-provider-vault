// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccRoleGoverningPolicy(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-policy")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccRoleGoverningPolicyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRoleGoverningPolicy(policyName, "soft-mandatory"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rgp_policy.test", "name", policyName),
					resource.TestCheckResourceAttr("vault_rgp_policy.test", "enforcement_level", "soft-mandatory"),
					resource.TestCheckResourceAttrSet("vault_rgp_policy.test", "policy"),
				),
			},
			{
				Config: testAccRoleGoverningPolicy(policyName, "hard-mandatory"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_rgp_policy.test", "name", policyName),
					resource.TestCheckResourceAttr("vault_rgp_policy.test", "enforcement_level", "hard-mandatory"),
					resource.TestCheckResourceAttrSet("vault_rgp_policy.test", "policy"),
				),
			},
		},
	})
}

func testAccRoleGoverningPolicyCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_rgp_policy" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		name := rs.Primary.Attributes["name"]
		data, err := client.Logical().Read(fmt.Sprintf("sys/policies/rgp/%s", name))
		if err != nil {
			return err
		}
		if data != nil {
			return fmt.Errorf("RGP policy %s still exists", name)
		}
	}
	return nil
}

func testAccRoleGoverningPolicy(policyName string, enforcementLevel string) string {
	return fmt.Sprintf(`
resource "vault_rgp_policy" "test" {
  name = "%s"
  enforcement_level = "%s"
  policy = <<EOT
main = rule {
  2+2 > 3
}
EOT
}`, policyName, enforcementLevel)
}
