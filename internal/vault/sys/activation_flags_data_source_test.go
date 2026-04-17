// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccActivationFlagsDataSource_basic tests basic data source read
func TestAccActivationFlagsDataSource_basic(t *testing.T) {
	dataSourceName := "data.vault_activation_flags.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsDataSourceConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "id", "sys/activation-flags"),
					resource.TestCheckResourceAttrSet(dataSourceName, "activated_flags.#"),
					resource.TestCheckResourceAttrSet(dataSourceName, "unactivated_flags.#"),
					testAccCheckActivationFlagsDataSourceValid(dataSourceName),
				),
			},
		},
	})
}

// TestAccActivationFlagsDataSource_withResource tests data source reading after resource creation
func TestAccActivationFlagsDataSource_withResource(t *testing.T) {
	dataSourceName := "data.vault_activation_flags.test"
	resourceName := "vault_activation_flags.test"
	var desiredFlags []string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			activatedFlags := testAccReadCurrentActivatedFlags(t)
			unactivatedFlags := testAccReadCurrentUnactivatedFlags(t)
			if len(unactivatedFlags) == 0 {
				t.Skip("Vault has no unactivated flags; resource-driven activation update path is not applicable")
			}
			desiredFlags = append(append([]string{}, activatedFlags...), unactivatedFlags[0])
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsDataSourceConfig_withResourceExplicit(desiredFlags),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "id", "sys/activation-flags"),
					testAccCheckActivationFlagsSetEqual(dataSourceName, desiredFlags),
					resource.TestCheckResourceAttrSet(dataSourceName, "unactivated_flags.#"),
					resource.TestCheckResourceAttr(resourceName, "id", "activation-flags"),
					testAccCheckActivationFlagsEqual(resourceName, desiredFlags),
				),
			},
		},
	})
}

// TestAccActivationFlagsDataSource_namespace tests data source with namespace
func TestAccActivationFlagsDataSource_namespace(t *testing.T) {
	dataSourceName := "data.vault_activation_flags.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsDataSourceConfig_namespace(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "id", "sys/activation-flags"),
					resource.TestCheckResourceAttrSet(dataSourceName, "activated_flags.#"),
					resource.TestCheckResourceAttrSet(dataSourceName, "unactivated_flags.#"),
				),
			},
		},
	})
}

// TestAccActivationFlagsDataSource_outputUsage tests using the data source in outputs
func TestAccActivationFlagsDataSource_outputUsage(t *testing.T) {
	dataSourceName := "data.vault_activation_flags.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsDataSourceConfig_withOutputs(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "id", "sys/activation-flags"),
					resource.TestCheckResourceAttrSet(dataSourceName, "activated_flags.#"),
					resource.TestCheckResourceAttrSet(dataSourceName, "unactivated_flags.#"),
				),
			},
		},
	})
}

// testAccCheckActivationFlagsDataSourceValid verifies the data source returns valid data
func testAccCheckActivationFlagsDataSourceValid(dataSourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		dataSourceState, ok := s.RootModule().Resources[dataSourceName]
		if !ok {
			return fmt.Errorf("data source not found: %s", dataSourceName)
		}

		// Verify ID is set
		if dataSourceState.Primary.ID == "" {
			return fmt.Errorf("data source ID is empty")
		}

		// Verify activated_flags is a valid list (even if empty)
		if _, ok := dataSourceState.Primary.Attributes["activated_flags.#"]; !ok {
			return fmt.Errorf("activated_flags.# attribute not found")
		}

		// Verify unactivated_flags is a valid list (even if empty)
		if _, ok := dataSourceState.Primary.Attributes["unactivated_flags.#"]; !ok {
			return fmt.Errorf("unactivated_flags.# attribute not found")
		}

		return nil
	}
}

// testAccCheckActivationFlagsConsistency verifies that the resource and data source have consistent data
func testAccCheckActivationFlagsConsistency(resourceName, dataSourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		dataSourceState, ok := s.RootModule().Resources[dataSourceName]
		if !ok {
			return fmt.Errorf("data source not found: %s", dataSourceName)
		}

		// Get activated flags count from resource
		resourceFlagsCount := resourceState.Primary.Attributes["activated_flags.#"]

		// Get activated flags count from data source
		dataSourceFlagsCount := dataSourceState.Primary.Attributes["activated_flags.#"]

		if resourceFlagsCount != dataSourceFlagsCount {
			return fmt.Errorf("activated_flags count mismatch: resource has %s, data source has %s",
				resourceFlagsCount, dataSourceFlagsCount)
		}

		return nil
	}
}

func testAccCheckActivationFlagsSetEqual(resourceName string, expected []string) resource.TestCheckFunc {
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "activated_flags.#", fmt.Sprintf("%d", len(expected))),
	}

	for _, flag := range expected {
		checks = append(checks, resource.TestCheckTypeSetElemAttr(resourceName, "activated_flags.*", flag))
	}

	return resource.ComposeTestCheckFunc(checks...)
}

// Config functions

func testAccActivationFlagsDataSourceConfig_basic() string {
	return `
data "vault_activation_flags" "test" {}
`
}

func testAccActivationFlagsDataSourceConfig_withResource() string {
	return `
# First read current state
data "vault_activation_flags" "current" {}

# Manage activation flags resource
resource "vault_activation_flags" "test" {
  # Maintain currently activated flags
  activated_flags = data.vault_activation_flags.current.activated_flags
}

# Read activation flags again to verify consistency
data "vault_activation_flags" "test" {
  depends_on = [vault_activation_flags.test]
}
`
}

func testAccActivationFlagsDataSourceConfig_withResourceExplicit(flags []string) string {
	quotedFlags := make([]string, 0, len(flags))
	for _, flag := range flags {
		quotedFlags = append(quotedFlags, fmt.Sprintf("%q", flag))
	}

	return fmt.Sprintf(`
resource "vault_activation_flags" "test" {
  activated_flags = [%s]
}

data "vault_activation_flags" "test" {
  depends_on = [vault_activation_flags.test]
}
`, strings.Join(quotedFlags, ", "))
}

func testAccActivationFlagsDataSourceConfig_namespace() string {
	return `
data "vault_activation_flags" "test" {
  namespace = "root"
}
`
}

func testAccActivationFlagsDataSourceConfig_withOutputs() string {
	return `
data "vault_activation_flags" "test" {}

# Example of using the data source in outputs
output "activated_features" {
  value = data.vault_activation_flags.test.activated_flags
}

output "unactivated_features" {
  value = data.vault_activation_flags.test.unactivated_flags
}

# Example of conditional logic based on activation flags
locals {
  # Check if a specific feature is activated (example)
  has_activated_flags = length(data.vault_activation_flags.test.activated_flags) > 0
}

output "has_activated_flags" {
  value = local.has_activated_flags
}
`
}

// Made with Bob
