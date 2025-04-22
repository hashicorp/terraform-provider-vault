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
	resourceName := "vault_password_policy.test"
	testPolicy := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"
	testPolicyUpdated := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\nrule \"charset\" {\n  charset = \"1234567890\"\nmin-chars = 1\n}\n"
	updatedConfig := testAccPasswordPolicyConfig(policyName, testPolicyUpdated)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicyConfig(policyName, testPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestAccPasswordPolicyNS(t *testing.T) {
	ns := acctest.RandomWithPrefix("ns")
	policyName := acctest.RandomWithPrefix("test-policy")
	resourceName := "vault_password_policy.test"
	testPolicy := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"
	testPolicyUpdated := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\nrule \"charset\" {\n  charset = \"1234567890\"\nmin-chars = 1\n}\n"
	updatedConfig := testAccPasswordPolicyConfigNS(ns, policyName, testPolicyUpdated)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicyConfigNS(ns, policyName, testPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "namespace", ns),
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "namespace", ns),
					resource.TestCheckResourceAttr(resourceName, "name", policyName),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			testutil.GetImportTestStepNS(t, ns, resourceName, updatedConfig),
			testutil.GetImportTestStepNSCleanup(t, updatedConfig),
		},
	})
}

func testAccPasswordPolicyConfig(policyName, policy string) string {
	return fmt.Sprintf(`
resource "vault_password_policy" "test" {
  name = "%s"
  policy = <<EOT
%s
EOT
}`, policyName, policy)
}

func testAccPasswordPolicyConfigNS(ns, policyName, policy string) string {
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
