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
	maxRetriesPerCycle := 1
	maxRetryCycles := 3
	updatedMaxRetriesPerCycle := 2
	updatedMaxRetryCycles := 5
	updatedConfig := testAccRotationPolicyConfig(policyName, updatedMaxRetriesPerCycle, updatedMaxRetryCycles)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRotationPolicyConfig(policyName, maxRetriesPerCycle, maxRetryCycles),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetriesPerCycle, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryCycles, "3"),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetriesPerCycle, "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryCycles, "5"),
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
	maxRetriesPerCycle := 1
	maxRetryCycles := 3
	updatedMaxRetriesPerCycle := 2
	updatedMaxRetryCycles := 5
	updatedConfig := testAccRotationPolicyConfigNS(ns, policyName, updatedMaxRetriesPerCycle, updatedMaxRetryCycles)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRotationPolicyConfigNS(ns, policyName, maxRetriesPerCycle, maxRetryCycles),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetriesPerCycle, "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryCycles, "3"),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetriesPerCycle, "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxRetryCycles, "5"),
				),
			},
			testutil.GetImportTestStepNS(t, ns, resourceName, updatedConfig),
			testutil.GetImportTestStepNSCleanup(t, updatedConfig),
		},
	})
}

func TestAccRotationPolicy_MissingFieldValidation(t *testing.T) {
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
				Config:      testAccRotationPolicyConfigMissingField(policyName),
				ExpectError: regexp.MustCompile(`max_retry_cycles`),
			},
		},
	})
}

func testAccRotationPolicyConfig(policyName string, maxRetriesPerCycle, maxRetryCycles int) string {
	return fmt.Sprintf(`
resource "vault_rotation_policy" "test" {
  name = %q
  max_retries_per_cycle = %d
  max_retry_cycles      = %d
}
`, policyName, maxRetriesPerCycle, maxRetryCycles)
}

func testAccRotationPolicyConfigNS(ns, policyName string, maxRetriesPerCycle, maxRetryCycles int) string {
	return fmt.Sprintf(`
resource "vault_namespace" "ns1" {
    path = %q
}

resource "vault_rotation_policy" "test" {
  namespace = vault_namespace.ns1.path
  name = %q
  max_retries_per_cycle = %d
  max_retry_cycles      = %d
}
`, ns, policyName, maxRetriesPerCycle, maxRetryCycles)
}

func testAccRotationPolicyConfigMissingField(policyName string) string {
	return fmt.Sprintf(`
resource "vault_rotation_policy" "test" {
  name = %q
  max_retries_per_cycle = 3
}
`, policyName)
}
