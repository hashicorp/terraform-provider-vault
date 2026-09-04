// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package generic_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccGenericEndpoint_rotateRoot exercises the action against a database
// secret backend, which is the deepest path shape Vault exposes for
// rotate-root: {mount}/rotate-root/{name}.
func TestAccGenericEndpoint_rotateRoot(t *testing.T) {
	values := testutil.SkipTestEnvUnset(t, "POSTGRES_ROTATE_ROOT_URL")
	connURL := values[0]
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_14_0),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGenericEndpointConfig_rotateRoot(backend, name, connURL),
			},
		},
	})
}

func TestAccGenericEndpoint_invalidPath(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_14_0),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccGenericEndpointConfig_invalidPath(),
				ExpectError: regexp.MustCompile(`Failed to write to Vault endpoint`),
			},
		},
	})
}

// TestAccGenericEndpoint_leadingSlash asserts the path validator rejects a
// leading slash at plan time, before any request reaches Vault.
func TestAccGenericEndpoint_leadingSlash(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_14_0),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccGenericEndpointConfig_path("/sys/leading-slash"),
				ExpectError: regexp.MustCompile(`contains leading/trailing`),
			},
		},
	})
}

// TestAccGenericEndpoint_invalidDataJSON asserts data_json is rejected at plan
// time when it is not a JSON object.
func TestAccGenericEndpoint_invalidDataJSON(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_14_0),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccGenericEndpointConfig_dataJSON("not-json"),
				ExpectError: regexp.MustCompile(`value must be a JSON object`),
			},
		},
	})
}

func testAccGenericEndpointConfig_rotateRoot(backend, name, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend       = vault_mount.db.path
  name          = "%s"
  allowed_roles = ["*"]

  postgresql {
    connection_url = "%s"
	username       = "rotate_root_user"
	password       = "rotate_root_password"
  }

  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.vault_generic_endpoint.test]
    }
  }
}

action "vault_generic_endpoint" "test" {
  config {
    path = "${vault_mount.db.path}/rotate-root/${vault_database_secret_backend_connection.test.name}"
  }
}
`, backend, name, connURL)
}

func testAccGenericEndpointConfig_invalidPath() string {
	return testAccGenericEndpointConfig_path("nonexistent-backend/rotate-root/nonexistent-connection")
}

func testAccGenericEndpointConfig_path(path string) string {
	return fmt.Sprintf(`
resource "terraform_data" "trigger" {
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.vault_generic_endpoint.test]
    }
  }
}

action "vault_generic_endpoint" "test" {
  config {
    path = "%s"
  }
}
`, path)
}

func testAccGenericEndpointConfig_dataJSON(dataJSON string) string {
	return fmt.Sprintf(`
resource "terraform_data" "trigger" {
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.vault_generic_endpoint.test]
    }
  }
}

action "vault_generic_endpoint" "test" {
  config {
    path      = "sys/policies/acl/tf-test"
    data_json = "%s"
  }
}
`, dataJSON)
}
