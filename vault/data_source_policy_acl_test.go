// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourcePolicyRead(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-policy")
	datasourceName := "data.vault_policy_acl.two"

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourcePolicyReadConfig(policyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasourceName, "name", policyName),
					resource.TestCheckResourceAttrSet(datasourceName, "policy"),
				),
			},
		},
	})
}

func testDataSourcePolicyReadConfig(policyName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "one" {
	name = "%s"

	policy = <<EOT
path "secret/my_app" {
	capabilities = ["update"]
}
EOT
}

data "vault_policy_acl" "two" {
	name = vault_policy.one.name
}

	`, policyName)
}
