// Copyright (c) 2017 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
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
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccRotationPolicyImportStateIDFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldName,
			},
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
			{
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, ns)
				},
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccRotationPolicyImportStateIDFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldName,
			},
		},
	})
}

func TestAccRotationPolicy_SameNameDifferentNamespaces(t *testing.T) {
	ns1 := acctest.RandomWithPrefix("ns")
	ns2 := acctest.RandomWithPrefix("ns")
	policyName := acctest.RandomWithPrefix("test-rotation-policy")
	resourceName1 := "vault_rotation_policy.test1"
	resourceName2 := "vault_rotation_policy.test2"
	maxRetriesPerCycle1 := 1
	maxRetryCycles1 := 3
	maxRetriesPerCycle2 := 2
	maxRetryCycles2 := 5
	config := testAccRotationPolicyConfigTwoNS(
		ns1,
		ns2,
		policyName,
		maxRetriesPerCycle1,
		maxRetryCycles1,
		maxRetriesPerCycle2,
		maxRetryCycles2,
	)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldNamespace, ns1),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMaxRetriesPerCycle, "1"),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMaxRetryCycles, "3"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldNamespace, ns2),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldName, policyName),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMaxRetriesPerCycle, "2"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMaxRetryCycles, "5"),
				),
			},
			{
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, ns1)
				},
				ResourceName:                         resourceName1,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccRotationPolicyImportStateIDFunc(resourceName1),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldNamespace,
			},
			{
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, ns2)
				},
				ResourceName:                         resourceName2,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccRotationPolicyImportStateIDFunc(resourceName2),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldNamespace,
			},
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

func testAccRotationPolicyConfigTwoNS(
	ns1, ns2, policyName string,
	maxRetriesPerCycle1, maxRetryCycles1, maxRetriesPerCycle2, maxRetryCycles2 int,
) string {
	return fmt.Sprintf(`
resource "vault_namespace" "ns1" {
		path = %q
}

resource "vault_namespace" "ns2" {
		path = %q
}

resource "vault_rotation_policy" "test1" {
	namespace = vault_namespace.ns1.path
	name = %q
	max_retries_per_cycle = %d
	max_retry_cycles      = %d
}

resource "vault_rotation_policy" "test2" {
	namespace = vault_namespace.ns2.path
	name = %q
	max_retries_per_cycle = %d
	max_retry_cycles      = %d
}
`, ns1, ns2, policyName, maxRetriesPerCycle1, maxRetryCycles1, policyName, maxRetriesPerCycle2, maxRetryCycles2)
}

func testAccRotationPolicyConfigMissingField(policyName string) string {
	return fmt.Sprintf(`
resource "vault_rotation_policy" "test" {
  name = %q
  max_retries_per_cycle = 3
}
`, policyName)
}

func testAccRotationPolicyImportStateIDFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return rs.Primary.Attributes[consts.FieldName], nil
	}
}
