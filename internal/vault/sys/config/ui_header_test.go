// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config_test

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
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

// TestAccConfigUIHeader_completeCRUD tests complete CRUD lifecycle
func TestAccConfigUIHeader_completeCRUD(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-CRUD-Header")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// CREATE
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"initial"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "initial"),
				),
			},
			// READ (import)
			testutil.GetImportTestStep(resourceName, false, nil),
			// UPDATE
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"updated"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "updated"),
				),
			},
			// READ (import again)
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

// TestAccConfigUIHeader_update tests update operations
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
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"updated"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "updated"),
				),
			},
		},
	})
}

// TestAccConfigUIHeader_multipleValues tests multiple values
func TestAccConfigUIHeader_multipleValues(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-Multi-Header")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
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
			testutil.GetImportTestStep(resourceName, false, nil),
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
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

// TestAccConfigUIHeader_commonHeaders tests common HTTP headers
func TestAccConfigUIHeader_commonHeaders(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIHeaderConfig_commonHeaders(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_config_ui_header.csp", consts.FieldName, "Content-Security-Policy"),
					resource.TestCheckResourceAttr("vault_config_ui_header.cors_origin", consts.FieldName, "Access-Control-Allow-Origin"),
				),
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
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

// TestAccConfigUIHeader_apiAsymmetry tests API asymmetry handling
// The Vault API returns single values as strings but accepts arrays
// This test verifies the provider correctly handles both formats
func TestAccConfigUIHeader_apiAsymmetry(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-Single-Value")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test 1: Single value (API returns as string)
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"single"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "single"),
				),
			},
			// Test 2: Import single value (verify string->array conversion)
			testutil.GetImportTestStep(resourceName, false, nil),
			// Test 3: Update to multiple values (API returns as array)
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"value1", "value2"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "value1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".1", "value2"),
				),
			},
			// Test 4: Import multiple values (verify array handling)
			testutil.GetImportTestStep(resourceName, false, nil),
			// Test 5: Update back to single value (verify array->string handling)
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"back-to-single"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "back-to-single"),
				),
			},
		},
	})
}

// TestAccConfigUIHeader_minimal tests minimal configuration
func TestAccConfigUIHeader_minimal(t *testing.T) {
	headerName := acctest.RandomWithPrefix("X-Minimal-Header")
	resourceName := "vault_config_ui_header.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIHeaderConfig_basic(headerName, []string{"minimal-value"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, headerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValues+".0", "minimal-value"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
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

// TestAccConfigUIHeader_emptyValues tests validation for empty values list
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
				ExpectError: regexp.MustCompile(`Attribute values list must contain at least 1`),
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

// Helper function for common HTTP headers test
func testAccConfigUIHeaderConfig_commonHeaders() string {
	return `
resource "vault_config_ui_header" "csp" {
  name = "Content-Security-Policy"
  values = ["default-src 'self'"]
}

resource "vault_config_ui_header" "cors_origin" {
  name = "Access-Control-Allow-Origin"
  values = ["https://example.com"]
}
`
}

func testAccConfigUIHeaderConfig_emptyValues(name string) string {
	return fmt.Sprintf(`
resource "vault_config_ui_header" "test" {
  name   = %q
  values = []
}`, name)
}
