// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
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
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldValues+".*", "value1"),
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
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldValues+".*", "initial"),
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
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldValues+".*", "updated"),
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
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldValues+".*", "value1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldValues+".*", "value2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldValues+".*", "value3"),
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

// TestAccConfigUIHeader_contentSecurityPolicy tests CSP header configuration
// This test validates the warning in the documentation about CSP overriding Vault's default
func TestAccConfigUIHeader_contentSecurityPolicy(t *testing.T) {
	resourceName := "vault_config_ui_header.csp"
	cspValue := "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIHeaderConfig_csp(cspValue),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "Content-Security-Policy"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldValues+".*", cspValue),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        "Content-Security-Policy",
				ImportStateVerifyIdentifierAttribute: consts.FieldName,
			},
			// Test updating CSP to a more restrictive policy
			{
				Config: testAccConfigUIHeaderConfig_csp("default-src 'self'"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "Content-Security-Policy"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldValues+".*", "default-src 'self'"),
				),
			},
		},
	})
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

// Helper function to generate CSP test configuration
func testAccConfigUIHeaderConfig_csp(cspValue string) string {
	return fmt.Sprintf(`
resource "vault_config_ui_header" "csp" {
  name = "Content-Security-Policy"
  values = [%q]
}`, cspValue)
}
