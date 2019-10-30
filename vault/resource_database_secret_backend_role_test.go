package vault

import (
	"fmt"
	"github.com/hashicorp/go-hclog"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
	tftest "github.com/terraform-providers/terraform-provider-vault/testing"
)

func TestAccDatabaseSecretBackendRole_import(t *testing.T) {
	cleanup, connURL := tftest.PrepareMySQLTestContainer(t)
	defer cleanup()

	backend := acctest.RandomWithPrefix("tf-test-db")
	dbName := acctest.RandomWithPrefix("db")
	name := acctest.RandomWithPrefix("role")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendRoleConfig_basic(name, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "db_name", dbName),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "default_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "max_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "creation_statements.0", "SELECT 1;"),
				),
			},
			{
				ResourceName:      "vault_database_secret_backend_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccDatabaseSecretBackendRole_basic(t *testing.T) {
	cleanup, connURL := tftest.PrepareMySQLTestContainer(t)
	defer cleanup()

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("role")
	dbName := acctest.RandomWithPrefix("db")
	testConf := testAccDatabaseSecretBackendRoleConfig_basic(name, dbName, backend, connURL)
	hclog.Default().Info("testConf:")
	hclog.Default().Info(testConf)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConf,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "db_name", dbName),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "default_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "max_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "creation_statements.0", "SELECT 1;"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendRoleConfig_updated(name, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "db_name", dbName),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "default_ttl", "1800"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "max_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.test", "creation_statements.0", "SELECT 1;"),
				),
			},
		},
	})
}

func testAccDatabaseSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_database_secret_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccDatabaseSecretBackendRoleConfig_basic(name, db, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]

  mysql {
	  connection_url = "%s"
      verify_connection = false
  }
}

resource "vault_database_secret_backend_role" "test" {
  backend = "${vault_mount.db.path}"
  db_name = "${vault_database_secret_backend_connection.test.name}"
  name = "%s"
  default_ttl = 3600
  max_ttl = 7200
  creation_statements = ["SELECT 1;"]
}
`, path, db, connURL, name)
}

func testAccDatabaseSecretBackendRoleConfig_updated(name, db, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]

  mysql {
	  connection_url = "%s"
      verify_connection = false
  }
}

resource "vault_database_secret_backend_role" "test" {
  backend = "${vault_mount.db.path}"
  db_name = "${vault_database_secret_backend_connection.test.name}"
  name = "%s"
  default_ttl = 1800
  max_ttl = 3600
  creation_statements = ["SELECT 1;"]
}
`, path, db, connURL, name)
}
