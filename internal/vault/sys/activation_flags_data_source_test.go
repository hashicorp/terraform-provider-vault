// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccActivationFlagsDataSource_basic tests basic data source read
func TestAccActivationFlagsDataSource_basic(t *testing.T) {
	dataSourceName := "data.vault_activation_flags.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccActivationFlagsEntPreCheck(t)
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
	testAccActivationFlagsEntPreCheck(t)

	unactivatedFlags := testAccReadCurrentUnactivatedFlags(t)
	if len(unactivatedFlags) == 0 {
		t.Skip("Vault has no unactivated flags; single-feature activation path is not applicable")
	}

	feature := unactivatedFlags[0]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsDataSourceConfig_withResource(feature),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "id", "sys/activation-flags"),
					resource.TestCheckTypeSetElemAttr(dataSourceName, "activated_flags.*", feature),
					resource.TestCheckResourceAttrSet(dataSourceName, "unactivated_flags.#"),
					resource.TestCheckResourceAttr(resourceName, "id", feature),
					resource.TestCheckResourceAttr(resourceName, "feature", feature),
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
			testAccActivationFlagsEntPreCheck(t)
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

// Config functions

func testAccActivationFlagsDataSourceConfig_basic() string {
	return `
data "vault_activation_flags" "test" {}
`
}

func testAccActivationFlagsDataSourceConfig_withResource(feature string) string {
	return fmt.Sprintf(`
resource "vault_activation_flags" "test" {
  feature = %q
}

data "vault_activation_flags" "test" {
  depends_on = [vault_activation_flags.test]
}
`, feature)
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
