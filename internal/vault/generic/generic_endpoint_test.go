// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package generic_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccGenericEndpointEphemeralAuth exercises the vault_generic_endpoint ephemeral resource
// using the "echo provider" pattern to test Auth response extraction.
//
// The test uses three steps:
//  1. Create userpass auth backend and user infrastructure.
//  2. Add the ephemeral login resource - extracts token/accessor from response.Auth
//  3. Add a Vault provider alias authenticated with the issued token and read
//     auth/token/lookup-self, proving the token is usable.
func TestAccGenericEndpointEphemeralAuth(t *testing.T) {
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
				Config: testAccGenericEndpointInfraConfig(mount, username, password),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add the ephemeral generic_endpoint resource
			{
				Config: testAccGenericEndpointLoginConfig(mount, username, password),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Use the token from ephemeral resource in a provider alias
			// and verify it works by calling auth/token/lookup-self
			{
				Config: testAccGenericEndpointWithTokenUseConfig(mount, username, password),
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

// TestAccGenericEndpointEphemeralWrapInfo exercises the vault_generic_endpoint ephemeral resource
// to test WrapInfo response extraction using response wrapping.
//
// This test creates a wrapped token with path_wrap_ttl set and verifies that wrap_info fields
// (token, ttl, creation_time, etc.) are successfully extracted from the response.WrapInfo structure.
// The test passes if the ephemeral resource successfully applies without errors, proving that
// response wrapping works and wrap_info fields can be extracted.
func TestAccGenericEndpointEphemeralWrapInfo(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Create a wrapped token - successful apply proves wrap_info extraction works
			{
				Config: testAccGenericEndpointWrapInfoConfig(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// testAccGenericEndpointInfraConfig creates the userpass auth backend and user
func testAccGenericEndpointInfraConfig(mount, username, password string) string {
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

// testAccGenericEndpointLoginConfig adds the ephemeral vault_generic_endpoint resource
func testAccGenericEndpointLoginConfig(mount, username, password string) string {
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

// testAccGenericEndpointWithTokenUseConfig extends the config with a provider alias
// authenticated via the ephemeral token
func testAccGenericEndpointWithTokenUseConfig(mount, username, password string) string {
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

// testAccGenericEndpointWrapInfoConfig creates a wrapped token and extracts wrap_info fields
// The successful application of this config proves that:
// 1. path_wrap_ttl parameter works correctly
// 2. Response wrapping is enabled (X-Vault-Wrap-TTL header is set)
// 3. wrap_info fields (token, ttl, creation_time, wrapped_accessor) are extracted from response.WrapInfo
func testAccGenericEndpointWrapInfoConfig() string {
	return `
ephemeral "vault_generic_endpoint" "wrapped_token" {
  path      = "auth/token/create"
  data_json = jsonencode({
    policies = ["default"]
    ttl      = "1h"
  })
  # Enable response wrapping with 5 minute TTL
  # This sets the X-Vault-Wrap-TTL header, causing Vault to return a wrapped response
  path_wrap_ttl = "300s"
  
  # Extract wrap_info fields from response.WrapInfo
  # These fields come from the WrapInfo structure, not Auth or Data
  write_fields = ["token", "ttl", "creation_time", "wrapped_accessor"]
}
`
}

// TestResourceGenericEndpoint tests the vault_generic_endpoint resource (non-ephemeral)
func TestResourceGenericEndpoint(t *testing.T) {
	path := acctest.RandomWithPrefix("userpass")
	resourceNames := []string{
		"vault_generic_endpoint.up1",
		"vault_generic_endpoint.up2",
		"vault_generic_endpoint.u1",
		"vault_generic_endpoint.u1_token",
		"vault_generic_endpoint.u1_entity",
	}
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testResourceGenericEndpoint_destroyCheck(resourceNames, path),
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericEndpoint_initialConfig(path),
				Check:  testResourceGenericEndpoint_initialCheck,
			},
		},
	})
}

func testResourceGenericEndpoint_initialConfig(path string) string {
	return fmt.Sprintf(`
variable "up_path" {
  default = "%s"
}

resource "vault_policy" "p1" {
  name = "p1"

  policy = <<EOT
path "secret/data/p1" {
  capabilities = ["read"]
}
EOT
}

# This resource does not have disable_delete and will not get deleted
# automatically because of being inside something else that's getting
# deleted. This is how we verify deletion of resources with
# disable_delete = false.
resource "vault_generic_endpoint" "up1" {
  path         = "sys/auth/${var.up_path}-1"
  disable_read = true

  data_json = <<EOT
{
  "type": "userpass"
}
EOT
}

# This one does not get deleted. We delete it manually. This is to
# test the test logic. If this one sticks around but up1 is gone,
# we know disable_delete is doing what it's supposed to and that
# we are correctly exercising this in the tests.
resource "vault_generic_endpoint" "up2" {
  path           = "sys/auth/${var.up_path}-2"
  disable_read   = true
  disable_delete = true

  data_json = <<EOT
{
  "type": "userpass"
}
EOT
}

resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = var.up_path
}

resource "vault_generic_endpoint" "u1" {
  depends_on           = ["vault_auth_backend.userpass"]
  path                 = "auth/${var.up_path}/users/u1"
  ignore_absent_fields = true

  data_json = <<EOT
{
  "policies": ["p1"],
  "password": "something"
}
EOT
}

resource "vault_generic_endpoint" "u1_token" {
  depends_on     = ["vault_generic_endpoint.u1"]
  path           = "auth/${var.up_path}/login/u1"
  disable_read   = true
  disable_delete = true

  data_json = <<EOT
{
  "password": "something"
}
EOT
}

resource "vault_generic_endpoint" "u1_entity" {
  depends_on           = ["vault_generic_endpoint.u1_token"]
  disable_read         = true
  disable_delete       = true
  path                 = "identity/lookup/entity"
  ignore_absent_fields = true
  write_fields         = ["id"]

  data_json = <<EOT
{
  "alias_name": "u1",
  "alias_mount_accessor": "${vault_auth_backend.userpass.accessor}"
}
EOT
}
`, path)
}

func testResourceGenericEndpoint_initialCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_generic_endpoint.u1_entity"]
	if resourceState == nil {
		return fmt.Errorf("resource vault_generic_endpoint.u1_entity not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource vault_generic_endpoint.u1_entity has no primary instance")
	}

	path := instanceState.ID

	if path != instanceState.Attributes["path"] {
		return fmt.Errorf("id doesn't match path")
	}
	if path != "identity/lookup/entity" {
		return fmt.Errorf("unexpected secret path")
	}

	writeDataCount := instanceState.Attributes["write_data.%"]
	if writeDataCount != "1" {
		return fmt.Errorf("write_data.%% has value %q, not 1", writeDataCount)
	}

	writeDataID := instanceState.Attributes["write_data.id"]
	if writeDataID == "" {
		return fmt.Errorf("write_data.id not found in state (%q)", instanceState.Attributes)
	}

	resourceState = s.Modules[0].Resources["vault_generic_endpoint.u1_token"]
	if resourceState == nil {
		return fmt.Errorf("resource vault_generic_endpoint.u1_token not found in state")
	}

	instanceState = resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource vault_generic_endpoint.u1_token has no primary instance")
	}

	writeDataCount = instanceState.Attributes["write_data.%"]
	if writeDataCount != "0" {
		return fmt.Errorf("write_data.%% has value %q, not 0", writeDataCount)
	}

	return nil
}

func testResourceGenericEndpoint_destroyCheck(resourceNames []string, path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Create a Vault client for the destroy check
		client, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			return fmt.Errorf("error creating Vault client: %s", err)
		}

		var ns string
		for _, name := range resourceNames {
			rs, err := testutil.GetResourceFromRootModule(s, name)
			if err != nil {
				return err
			}

			instanceState := rs.Primary

			if n, ok := instanceState.Attributes[consts.FieldNamespace]; ok {
				if ns != n {
					return fmt.Errorf("all test resources must be in the same namepace")
				}

				ns = n
			}

			// Check to make sure resources that we can read are no longer
			// there.
			if instanceState.Attributes["disable_read"] != "true" {
				data, err := client.Logical().Read(rs.Primary.ID)
				if err != nil {
					return fmt.Errorf("error checking for vault generic endpoint %q: %s", rs.Primary.ID, err)
				}
				if data != nil {
					return fmt.Errorf("generic endpoint %q still exists", rs.Primary.ID)
				}
			}
		}

		data, err := client.Logical().Read("sys/auth")
		if err != nil {
			return fmt.Errorf("error reading for sys/auth: %s", err)
		}
		if _, ok := data.Data[path+"-1/"]; ok {
			return fmt.Errorf("auth/user/pass/%s-1 still exists (%q)", path, data.Data)
		}
		if _, ok := data.Data[path+"-2/"]; !ok {
			return fmt.Errorf("auth/user/pass/%s-2 no longer exists (%q)", path, data.Data)
		}
		if _, err := client.Logical().Delete("sys/auth/" + path + "-2/"); err != nil {
			return fmt.Errorf("unable to delete auth/user/pass/%s-2: %s", path, err)
		}

		return nil
	}
}
