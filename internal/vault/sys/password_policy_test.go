// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
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
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicyConfig(policyName, testPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPolicy),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPolicy),
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
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicyConfigNS(ns, policyName, testPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPolicy),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPolicy),
				),
			},
			testutil.GetImportTestStepNS(t, ns, resourceName, updatedConfig),
			testutil.GetImportTestStepNSCleanup(t, updatedConfig),
		},
	})
}

func TestAccPasswordPolicy_Muxing(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-policy")
	policyNameUpdated := acctest.RandomWithPrefix("test-policy-updated")
	resourceName := "vault_password_policy.test"
	testPolicy := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"
	testPolicyUpdated := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\nrule \"charset\" {\n  charset = \"1234567890\"\nmin-chars = 1\n}\n"
	updatedConfig := testAccPasswordPolicyConfig(policyNameUpdated, testPolicyUpdated)
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"vault": {
						// 4.8.0 is not multiplexed
						VersionConstraint: "4.8.0",
						Source:            "hashicorp/vault",
					},
				},
				Config: testAccPasswordPolicyConfig(policyName, testPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPolicy),
				),
			},
			// upgrade to new Muxed TFVP, ensure plan is seamless
			{
				ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
				Config:                   testAccPasswordPolicyConfig(policyName, testPolicy),
				PlanOnly:                 true,
			},
			// update name to ensure resource can get recreated on name updates
			{
				ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
				Config:                   updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyNameUpdated),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPolicy),
				),
			},
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

func TestAccPasswordPolicyEntropySource(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-policy")
	resourceName := "vault_password_policy.test"
	testPolicy := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicyConfigWithEntropySource(policyName, testPolicy, "platform"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEntropySource, "platform"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPolicy),
				),
			},
			{
				Config: testAccPasswordPolicyConfigWithEntropySource(policyName, testPolicy, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEntropySource, ""),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPolicy),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldEntropySource),
		},
	})
}

func TestAccPasswordPolicyEntropySourceSeal(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-policy")
	resourceName := "vault_password_policy.test"
	testPolicy := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t) // Only run this test on enterprise
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPasswordPolicyConfigWithEntropySource(policyName, testPolicy, "seal"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEntropySource, "seal"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldPolicy),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldEntropySource),
		},
	})
}

func TestAccPasswordPolicyEntropySourceValidation(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-policy")
	testPolicy := "length = 20\nrule \"charset\" {\n  charset = \"abcde\"\n}\n"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccPasswordPolicyConfigWithEntropySource(policyName, testPolicy, "invalid"),
				ExpectError: regexp.MustCompile(`unsupported entropy source invalid`),
			},
		},
	})
}

func testAccPasswordPolicyConfigWithEntropySource(policyName, policy, entropySource string) string {
	return fmt.Sprintf(`
resource "vault_password_policy" "test" {
  name = "%s"
  entropy_source = "%s"
  policy = <<EOT
%s
EOT
}`, policyName, entropySource, policy)
}
