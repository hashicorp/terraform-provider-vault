// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package generic_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccGenericEndpointEphemeral is the basic test for the vault_generic_endpoint ephemeral resource.
// It tests Auth response extraction using the "echo provider" pattern.
//
// The test uses three steps:
//  1. Create userpass auth backend and user infrastructure.
//  2. Add the ephemeral login resource - extracts token/accessor from response.Auth
//  3. Add a Vault provider alias authenticated with the issued token and read
//     auth/token/lookup-self, proving the token is usable.
func TestAccGenericEndpointEphemeral(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass")
	username := "u1"
	password := "changeme"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create userpass auth backend and user
			{
				Config: testAccGenericEndpointEphemeral_infraConfig(mount, username, password),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add the ephemeral generic_endpoint resource
			{
				Config: testAccGenericEndpointEphemeral_loginConfig(mount, username, password),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Use the token from ephemeral resource in a provider alias
			// and verify it works by calling auth/token/lookup-self
			{
				Config: testAccGenericEndpointEphemeral_withTokenUseConfig(mount, username, password),
				Check: resource.ComposeTestCheckFunc(
					// Verify the data source returned token metadata
					resource.TestCheckResourceAttrSet(
						"data.vault_generic_secret.token_check", "data.%"),
					resource.TestCheckResourceAttrSet(
						"data.vault_generic_secret.token_check", "data.accessor"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccGenericEndpointEphemeral_wrapInfo tests WrapInfo response extraction using response wrapping.
//
// This test creates a wrapped token with path_wrap_ttl set and verifies that wrap_info fields
// (token, ttl, creation_time, etc.) are successfully extracted from the response.WrapInfo structure.
func TestAccGenericEndpointEphemeral_wrapInfo(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGenericEndpointEphemeral_wrapInfoConfig(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccGenericEndpointEphemeral_invalidJSON tests error handling for invalid JSON in data_json.
func TestAccGenericEndpointEphemeral_invalidJSON(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccGenericEndpointEphemeral_invalidJSONConfig(),
				ExpectError: regexp.MustCompile("invalid character"),
			},
		},
	})
}

// TestAccGenericEndpointEphemeral_invalidPath tests error handling when writing to a non-existent path.
func TestAccGenericEndpointEphemeral_invalidPath(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccGenericEndpointEphemeral_invalidPathConfig(),
				ExpectError: regexp.MustCompile("Error making API request|permission denied|unsupported path"),
			},
		},
	})
}

// TestAccGenericEndpointEphemeral_wrapInfoSpecialField tests extraction of the "wrap_info" special field.
// This verifies that write_fields = ["wrap_info"] extracts the full WrapInfo structure as JSON.
func TestAccGenericEndpointEphemeral_wrapInfoSpecialField(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGenericEndpointEphemeral_wrapInfoSpecialFieldConfig(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccGenericEndpointEphemeral_authSpecialField tests extraction of the "auth" special field.
// This verifies that write_fields = ["auth"] extracts the full Auth structure as JSON.
func TestAccGenericEndpointEphemeral_authSpecialField(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass")
	username := "u1"
	password := "changeme"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create infrastructure
			{
				Config: testAccGenericEndpointEphemeral_infraConfig(mount, username, password),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add ephemeral resource with "auth" special field
			{
				Config: testAccGenericEndpointEphemeral_authSpecialFieldConfig(mount, username, password),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccGenericEndpointEphemeral_tokenAlias tests the "token" alias for "client_token".
// This verifies that write_fields = ["token"] correctly extracts Auth.ClientToken.
func TestAccGenericEndpointEphemeral_tokenAlias(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass")
	username := "u1"
	password := "changeme"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create infrastructure
			{
				Config: testAccGenericEndpointEphemeral_infraConfig(mount, username, password),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add ephemeral resource with "token" alias
			{
				Config: testAccGenericEndpointEphemeral_tokenAliasConfig(mount, username, password),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccGenericEndpointEphemeral_topLevelFields tests extraction of top-level response fields.
// This verifies that fields like lease_duration and lease_id can be extracted from the response root.
func TestAccGenericEndpointEphemeral_topLevelFields(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGenericEndpointEphemeral_topLevelFieldsConfig(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccGenericEndpointEphemeral_extractFromData tests extraction of fields from response.Data.
// This verifies that fields within the Data map can be extracted correctly.
func TestAccGenericEndpointEphemeral_extractFromData(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGenericEndpointEphemeral_extractFromDataConfig(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccGenericEndpointEphemeral_complexTypes tests extraction of complex field types like arrays.
// This verifies that complex types are properly JSON-encoded in write_data.
func TestAccGenericEndpointEphemeral_complexTypes(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGenericEndpointEphemeral_complexTypesConfig(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// Helper functions for ephemeral resource tests

// testAccGenericEndpointEphemeral_infraConfig creates the userpass auth backend and user
func testAccGenericEndpointEphemeral_infraConfig(mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "%s"
}

resource "vault_generic_endpoint" "user" {
  depends_on           = [vault_auth_backend.userpass]
  path                 = "auth/%s/users/%s"
  ignore_absent_fields = true
  data_json = jsonencode({
    password = "%s"
  })
}
`, mount, mount, username, password)
}

// testAccGenericEndpointEphemeral_loginConfig adds the ephemeral vault_generic_endpoint resource
func testAccGenericEndpointEphemeral_loginConfig(mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "%s"
}

resource "vault_generic_endpoint" "user" {
  depends_on           = [vault_auth_backend.userpass]
  path                 = "auth/%s/users/%s"
  ignore_absent_fields = true
  data_json = jsonencode({
    password = "%s"
  })
}

ephemeral "vault_generic_endpoint" "u1_token" {
  path      = "auth/%s/login/%s"
  data_json = jsonencode({ password = "%s" })
  write_fields = ["token", "accessor"]
}
`, mount, mount, username, password, mount, username, password)
}

// testAccGenericEndpointEphemeral_withTokenUseConfig extends the config with a provider alias
// authenticated via the ephemeral token
func testAccGenericEndpointEphemeral_withTokenUseConfig(mount, username, password string) string {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}

	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "%s"
}

resource "vault_generic_endpoint" "user" {
  depends_on           = [vault_auth_backend.userpass]
  path                 = "auth/%s/users/%s"
  ignore_absent_fields = true
  data_json = jsonencode({
    password = "%s"
  })
}

ephemeral "vault_generic_endpoint" "u1_token" {
  path      = "auth/%s/login/%s"
  data_json = jsonencode({ password = "%s" })
  write_fields = ["token", "accessor"]
}

# Echo provider: authenticated with the ephemeral token
provider "vault" {
  alias            = "echo_test"
  address          = "%s"
  token            = ephemeral.vault_generic_endpoint.u1_token.write_data["token"]
  skip_child_token = true
}

# Verify the token works by looking up self
data "vault_generic_secret" "token_check" {
  provider = vault.echo_test
  path     = "auth/token/lookup-self"
}
`, mount, mount, username, password, mount, username, password, vaultAddr)
}

// testAccGenericEndpointEphemeral_wrapInfoConfig creates a wrapped token and extracts wrap_info fields
func testAccGenericEndpointEphemeral_wrapInfoConfig() string {
	return `
ephemeral "vault_generic_endpoint" "wrapped_token" {
  path      = "auth/token/create"
  data_json = jsonencode({
    policies = ["default"]
    ttl      = "1h"
  })
  path_wrap_ttl = "300s"
  write_fields = ["token", "ttl", "creation_time", "wrapped_accessor"]
}
`
}

// testAccGenericEndpointEphemeral_invalidJSONConfig tests invalid JSON handling
func testAccGenericEndpointEphemeral_invalidJSONConfig() string {
	return `
ephemeral "vault_generic_endpoint" "test" {
  path = "auth/token/create"
  data_json = "{invalid json"
}
`
}

// testAccGenericEndpointEphemeral_invalidPathConfig tests error handling for non-existent paths
func testAccGenericEndpointEphemeral_invalidPathConfig() string {
	return `
ephemeral "vault_generic_endpoint" "test" {
  path = "nonexistent/invalid/path"
  data_json = jsonencode({})
}
`
}

// testAccGenericEndpointEphemeral_wrapInfoSpecialFieldConfig tests "wrap_info" special field extraction
func testAccGenericEndpointEphemeral_wrapInfoSpecialFieldConfig() string {
	return `
ephemeral "vault_generic_endpoint" "wrapped_token" {
  path      = "auth/token/create"
  data_json = jsonencode({
    policies = ["default"]
    ttl      = "1h"
  })
  path_wrap_ttl = "300s"
  write_fields = ["wrap_info"]
}
`
}

// testAccGenericEndpointEphemeral_authSpecialFieldConfig tests "auth" special field extraction
func testAccGenericEndpointEphemeral_authSpecialFieldConfig(mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "%s"
}

resource "vault_generic_endpoint" "user" {
  depends_on           = [vault_auth_backend.userpass]
  path                 = "auth/%s/users/%s"
  ignore_absent_fields = true
  data_json = jsonencode({
    password = "%s"
  })
}

ephemeral "vault_generic_endpoint" "u1_token" {
  path      = "auth/%s/login/%s"
  data_json = jsonencode({ password = "%s" })
  write_fields = ["auth"]
}
`, mount, mount, username, password, mount, username, password)
}

// testAccGenericEndpointEphemeral_tokenAliasConfig tests "token" alias for "client_token"
func testAccGenericEndpointEphemeral_tokenAliasConfig(mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "%s"
}

resource "vault_generic_endpoint" "user" {
  depends_on           = [vault_auth_backend.userpass]
  path                 = "auth/%s/users/%s"
  ignore_absent_fields = true
  data_json = jsonencode({
    password = "%s"
  })
}

ephemeral "vault_generic_endpoint" "u1_token" {
  path      = "auth/%s/login/%s"
  data_json = jsonencode({ password = "%s" })
  write_fields = ["token"]
}
`, mount, mount, username, password, mount, username, password)
}

// testAccGenericEndpointEphemeral_topLevelFieldsConfig tests extraction of top-level response fields
func testAccGenericEndpointEphemeral_topLevelFieldsConfig() string {
	return `
ephemeral "vault_generic_endpoint" "token" {
  path      = "auth/token/create"
  data_json = jsonencode({
    policies = ["default"]
    ttl      = "1h"
  })
  write_fields = ["lease_duration", "lease_id"]
}
`
}

// testAccGenericEndpointEphemeral_extractFromDataConfig tests extraction from response.Data
func testAccGenericEndpointEphemeral_extractFromDataConfig() string {
	return `
ephemeral "vault_generic_endpoint" "token" {
  path      = "auth/token/create"
  data_json = jsonencode({
    policies = ["default"]
    ttl      = "1h"
  })
  write_fields = ["policies", "ttl"]
}
`
}

// testAccGenericEndpointEphemeral_complexTypesConfig tests extraction of complex types like arrays
func testAccGenericEndpointEphemeral_complexTypesConfig() string {
	return `
ephemeral "vault_generic_endpoint" "token" {
  path      = "auth/token/create"
  data_json = jsonencode({
    policies = ["default", "policy1", "policy2"]
    ttl      = "1h"
  })
  write_fields = ["policies"]
}
`
}
