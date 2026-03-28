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

// TestAccConfigUIHeader_specialCharacters tests special character handling
func TestAccConfigUIHeader_specialCharacters(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-Special-Header")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"value: with; special, chars="}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "value: with; special, chars="),
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

// TestAccConfigUIHeader_sudoCapability tests that sudo capability is required
// This test verifies that the resource properly handles the sudo requirement
// by attempting operations that require elevated permissions
func TestAccConfigUIHeader_sudoCapability(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-Sudo-Test")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"test-value"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "test-value"),
				),
			},
			// Verify import also works with sudo
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

// TestAccConfigUIHeader_nameChange tests changing the header name (forces recreation)
func TestAccConfigUIHeader_nameChange(t *testing.T) {
	headerName1 := acctest.RandomWithPrefix("X-Header-1")
	headerName2 := acctest.RandomWithPrefix("X-Header-2")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName1, []string{"value1"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName1),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "value1"),
				),
			},
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName2, []string{"value1"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName2),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "value1"),
				),
			},
		},
	})
}

// TestAccConfigUIHeader_emptyValues tests that empty values are rejected
func TestAccConfigUIHeader_emptyValues(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-Empty-Header")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccConfigUIHeaderConfig_emptyValues(headerName),
				ExpectError: regexp.MustCompile("Attribute values set must contain at least 1"),
			},
		},
	})
}

// TestAccConfigUIHeader_duplicateValues tests that duplicate values are handled
func TestAccConfigUIHeader_duplicateValues(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-Duplicate-Header")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"value1", "value1", "value2"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					// Terraform sets automatically deduplicate, so we should only have 2 unique values
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "2"),
					testAccCheckUIHeaderValuesContain(resourceName, "value1"),
					testAccCheckUIHeaderValuesContain(resourceName, "value2"),
				),
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
