// Copyright (c) 2017 HashiCorp, Inc.
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

func TestAccRotationPolicy(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-rotation-policy")
	resourceName := "vault_rotation_policy.test"
	policy := `{"max_retries_per_cycle":1,"max_retry_cycles":3}`
	updatedPolicy := `{"max_retries_per_cycle":2,"max_retry_cycles":5}`
	updatedConfig := testAccRotationPolicyConfig(policyName, updatedPolicy)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRotationPolicyConfig(policyName, policy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicy, policy),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicy, updatedPolicy),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestAccRotationPolicyNS(t *testing.T) {
	ns := acctest.RandomWithPrefix("ns")
	policyName := acctest.RandomWithPrefix("test-rotation-policy")
	resourceName := "vault_rotation_policy.test"
	policy := `{"max_retries_per_cycle":1,"max_retry_cycles":3}`
	updatedPolicy := `{"max_retries_per_cycle":2,"max_retry_cycles":5}`
	updatedConfig := testAccRotationPolicyConfigNS(ns, policyName, updatedPolicy)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRotationPolicyConfigNS(ns, policyName, policy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicy, policy),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicy, updatedPolicy),
				),
			},
			testutil.GetImportTestStepNS(t, ns, resourceName, updatedConfig),
			testutil.GetImportTestStepNSCleanup(t, updatedConfig),
		},
	})
}

func TestAccRotationPolicy_EmptyPolicyValidation(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-rotation-policy")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccRotationPolicyConfig(policyName, ""),
				ExpectError: regexp.MustCompile(`must not be empty|at least 1`),
			},
		},
	})
}

func TestAccRotationPolicy_JSONEncode(t *testing.T) {
	policyName := acctest.RandomWithPrefix("test-rotation-policy")
	resourceName := "vault_rotation_policy.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRotationPolicyConfigJSONEncode(policyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestMatchResourceAttr(resourceName, consts.FieldPolicy, regexp.MustCompile(`"max_retries_per_cycle":3`)),
					resource.TestMatchResourceAttr(resourceName, consts.FieldPolicy, regexp.MustCompile(`"max_retry_cycles":5`)),
				),
			},
		},
	})
}

func testAccRotationPolicyConfig(policyName, policy string) string {
	return fmt.Sprintf(`
resource "vault_rotation_policy" "test" {
  name = %q
  policy = %q
}
`, policyName, policy)
}

func testAccRotationPolicyConfigNS(ns, policyName, policy string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "ns1" {
    path = %q
}

resource "vault_rotation_policy" "test" {
  namespace = vault_namespace.ns1.path
  name = %q
  policy = %q
}
`, ns, policyName, policy)
}

func testAccRotationPolicyConfigJSONEncode(policyName string) string {
	return fmt.Sprintf(`
resource "vault_rotation_policy" "test" {
	name = %q
	policy = jsonencode({
		max_retries_per_cycle = 3
		max_retry_cycles      = 5
	})
}
`, policyName)
}
