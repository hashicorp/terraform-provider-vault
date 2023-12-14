// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPasswordPolicy(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-policy")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicyConfig(policyName, "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_password_policy.test", "name", policyName),
					resource.TestCheckResourceAttrSet("vault_password_policy.test", "policy"),
				),
			},
			{
				Config: testAccPasswordPolicyConfig(policyName, "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\nrule \"charset\" {\n  charset = \"1234567890\"\nmin-chars = 1\n}\n"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_password_policy.test", "name", policyName),
					resource.TestCheckResourceAttrSet("vault_password_policy.test", "policy"),
				),
			},
		},
	})
}

func testAccPasswordPolicyConfig(policyName string, policy string) string {
	return fmt.Sprintf(`
resource "vault_password_policy" "test" {
  name = "%s"
   policy = <<EOT
%s
EOT
}`, policyName, policy)
}
