package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"os"
	"testing"
)

func TestAccEndpointGoverningPolicy(t *testing.T) {
	isEnterprise := os.Getenv("TF_ACC_ENTERPRISE")
	if isEnterprise == "" {
		t.Skip("TF_ACC_ENTERPRISE is not set, test is applicable only for Enterprise version of Vault")
	}

	policyName := acctest.RandomWithPrefix("test-policy")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccEndpointGoverningPolicyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccEndpointGoverningPolicy(policyName, "test/*", "soft-mandatory"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_egp_policy.test", "name", policyName),
					resource.TestCheckResourceAttr("vault_egp_policy.test", "paths.0", "test/*"),
					resource.TestCheckResourceAttr("vault_egp_policy.test", "enforcement_level", "soft-mandatory"),
					resource.TestCheckResourceAttrSet("vault_egp_policy.test", "policy"),
				),
			},
			{
				Config: testAccEndpointGoverningPolicy(policyName, "test2/*", "hard-mandatory"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_egp_policy.test", "name", policyName),
					resource.TestCheckResourceAttr("vault_egp_policy.test", "paths.0", "test2/*"),
					resource.TestCheckResourceAttr("vault_egp_policy.test", "enforcement_level", "hard-mandatory"),
					resource.TestCheckResourceAttrSet("vault_egp_policy.test", "policy"),
				),
			},
		},
	})
}

func testAccEndpointGoverningPolicyCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_egp_policy" {
			continue
		}
		name := rs.Primary.Attributes["name"]
		data, err := client.Logical().Read(fmt.Sprintf("sys/policies/egp/%s", name))
		if err != nil {
			return err
		}
		if data != nil {
			return fmt.Errorf("EGP policy %s still exists", name)
		}
	}
	return nil
}

func testAccEndpointGoverningPolicy(policyName string, path string, enforcementLevel string) string {
	return fmt.Sprintf(`
resource "vault_egp_policy" "test" {
  name = "%s"
  paths = ["%s"]
  enforcement_level = "%s"
  policy = <<EOT
main = rule {
  2+2 > 3
}
EOT
}`, policyName, path, enforcementLevel)
}
