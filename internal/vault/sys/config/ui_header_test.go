// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config_test

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
	// "github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccConfigUIHeader tests basic resource creation and import
func TestAccConfigUIHeader(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-Test-Header")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"value1"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "value1"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        headerName,
				ImportStateVerifyIdentifierAttribute: consts.FieldName,
			},
		},
	})
}

// TestAccConfigUIHeader_update tests update operations, multiple values, and import verification
func TestAccConfigUIHeader_update(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-Update-Header")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"initial"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "initial"),
				),
			},
			// Verify import works
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        headerName,
				ImportStateVerifyIdentifierAttribute: consts.FieldName,
			},
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"updated"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "updated"),
				),
			},
			// Verify import still works after update
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        headerName,
				ImportStateVerifyIdentifierAttribute: consts.FieldName,
			},
			// Test multiple values
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"value1", "value2", "value3"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "3"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "value1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".1", "value2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".2", "value3"),
				),
			},
			// Verify import works with multiple values
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        headerName,
				ImportStateVerifyIdentifierAttribute: consts.FieldName,
			},
		},
	})
}

// Helper function to check if a value exists in the values set
func testAccCheckUIHeaderValuesContain(resourceName, expectedValue string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		// Check if the expected value exists in any of the values
		for key, value := range rs.Primary.Attributes {
			if regexp.MustCompile(`^values\.\d+$`).MatchString(key) && value == expectedValue {
				return nil
			}
		}

		return fmt.Errorf("expected value %q not found in values set", expectedValue)
	}
}

// Helper function to generate test configuration
func testAccConfigUIHeaderConfig_basic(name string, values []string) string {
	valuesStr := ""
	for _, v := range values {
		valuesStr += fmt.Sprintf("    %q,\n", v)
	}

	return fmt.Sprintf(`
resource "vault_config_ui_header" "test" {
  name = %q
  values = [
%s  ]
}`, name, valuesStr)
}

// Helper function to generate test configuration with empty values
func testAccConfigUIHeaderConfig_emptyValues(name string) string {
	return fmt.Sprintf(`
resource "vault_config_ui_header" "test" {
  name = %q
  values = []
}`, name)
}
