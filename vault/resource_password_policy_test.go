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

func TestAccPasswordPolicy(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-policy")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccPasswordPolicyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicy(policyName, "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_password_policy.test", "name", policyName),
					resource.TestCheckResourceAttrSet("vault_password_policy.test", "policy"),
				),
			},
			{
				Config: testAccPasswordPolicy(policyName, "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\nrule \"charset\" {\n  charset = \"1234567890\"\nmin-chars = 1\n}\n"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_password_policy.test", "name", policyName),
					resource.TestCheckResourceAttrSet("vault_password_policy.test", "policy"),
				),
			},
		},
	})
}

func TestAccPasswordPolicy_import(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-policy")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccPasswordPolicyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicy(policyName, "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_password_policy.test", "name", policyName),
					resource.TestCheckResourceAttrSet("vault_password_policy.test", "policy"),
				),
			},
			{
				ResourceName:      "vault_password_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccPasswordPolicyCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_password_policy" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		name := rs.Primary.Attributes["name"]
		data, err := client.Logical().Read(fmt.Sprintf("sys/policies/password/%s", name))
		if err != nil {
			return err
		}
		if data != nil {
			return fmt.Errorf("Password policy %s still exists", name)
		}
	}
	return nil
}

func testAccPasswordPolicy(policyName string, policy string) string {
	return fmt.Sprintf(`
resource "vault_password_policy" "test" {
  name = "%s"
   policy = <<EOT
%s
EOT
}`, policyName, policy)
}
