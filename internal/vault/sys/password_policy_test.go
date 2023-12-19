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
	ns := acctest.RandomWithPrefix("ns")
	policyName := acctest.RandomWithPrefix("test-policy")
	resourceName := "vault_password_policy.test"
	testPolicy := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"
	testPolicyUpdated := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\nrule \"charset\" {\n  charset = \"1234567890\"\nmin-chars = 1\n}\n"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicyConfig(ns, policyName, testPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "namespace", ns),
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			{
				Config: testAccPasswordPolicyConfig(ns, policyName, testPolicyUpdated),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "namespace", ns),
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			// {
			// 	// unfortunately two steps are needed when testing import,
			// 	// since the tf-plugin-sdk does not allow for specifying environment variables :(
			// 	// neither does have any support for generic post-step functions.
			// 	// It is possible that this will cause issues if we ever want to support parallel tests.
			// 	// We would have to update the SDK to suport specifying extra env vars by step.
			// 	PreConfig: func() {
			// 		t.Setenv(consts.EnvVarVaultNamespaceImport, ns)
			// 	},
			// 	ImportState:       true,
			// 	ImportStateVerify: true,
			// 	ResourceName:      resourceName,
			// },
			// {
			// 	// needed for the import step above :(
			// 	Config: testAccPasswordPolicyConfig(ns, policyName, testPolicyUpdated),
			// 	PreConfig: func() {
			// 		os.Unsetenv(consts.EnvVarVaultNamespaceImport)
			// 	},
			// 	PlanOnly: true,
			// },
		},
	})
}

func testAccPasswordPolicyConfig(ns, policyName, policy string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "ns1" {
    path = "%s"
}

resource "vault_password_policy" "test" {
  namespace = vault_namespace.ns1.path
  name = "%s"
  policy = <<EOT
%s
EOT
}`, ns, policyName, policy)
}
