// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package rotate_test

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

func TestAccSecretBackendRotateRoot_basic(t *testing.T) {
	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
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
				Config: testAccSecretBackendRotateRootConfig_basic(backend, name, connURL),
			},
		},
	})
}

func TestAccSecretBackendRotateRoot_invalidBackend(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_14_0),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccSecretBackendRotateRootConfig_invalidBackend(),
				ExpectError: regexp.MustCompile(`Failed to rotate root credentials`),
			},
		},
	})
}

func testAccSecretBackendRotateRootConfig_basic(backend, name, connURL string) string {
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
  }

  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.vault_secret_backend_rotate_root.test]
    }
  }
}

action "vault_secret_backend_rotate_root" "test" {
  config {
    backend = vault_mount.db.path
    name    = vault_database_secret_backend_connection.test.name
  }
}
`, backend, name, connURL)
}

func testAccSecretBackendRotateRootConfig_invalidBackend() string {
	return `
resource "terraform_data" "trigger" {
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.vault_secret_backend_rotate_root.test]
    }
  }
}

action "vault_secret_backend_rotate_root" "test" {
  config {
    backend = "nonexistent-backend"
    name    = "nonexistent-connection"
  }
}
`
}
