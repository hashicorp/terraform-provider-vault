package vault

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccDatabaseSecretBackendStaticRole_import(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	username := acctest.RandomWithPrefix("user")
	dbName := acctest.RandomWithPrefix("db")
	name := acctest.RandomWithPrefix("staticrole")

	if err := createTestUser(connURL, username); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_basic(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "username", username),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "db_name", dbName),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "rotation_period", "3600"),
				),
			},
			{
				ResourceName:      "vault_database_secret_backend_static_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccDatabaseSecretBackendStaticRole_basic(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("staticrole")
	username := acctest.RandomWithPrefix("user")
	dbName := acctest.RandomWithPrefix("db")

	if err := createTestUser(connURL, username); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_basic(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "username", username),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "db_name", dbName),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "rotation_period", "3600"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_updated(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "username", username),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "db_name", dbName),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "rotation_period", "1800"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "rotation_statements.0", "SELECT 1;"),
				),
			},
		},
	})
}

func testAccDatabaseSecretBackendStaticRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_database_secret_backend_static_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("sttatic role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func createTestUser(connURL, username string) error {
	ctx := context.Background()
	db, err := sql.Open("mysql", connURL)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	stmt, err := tx.PrepareContext(ctx, fmt.Sprintf("CREATE USER '%s'@'localhost' IDENTIFIED BY 'password';", username))
	if err != nil {
		return err
	}
	defer func() {
		_ = stmt.Close()
	}()
	if _, err := stmt.ExecContext(ctx); err != nil {
		return err
	}
	return nil
}

func testAccDatabaseSecretBackendStaticRoleConfig_basic(name, username, db, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["*"]

  mysql {
	  connection_url = "%s"
  }
}

resource "vault_database_secret_backend_static_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  username = "%s"
  rotation_period = 3600
  rotation_statements = ["ALTER USER '{{username}}'@'localhost' IDENTIFIED BY '{{password}}';"]
}
`, path, db, connURL, name, username)
}

func testAccDatabaseSecretBackendStaticRoleConfig_updated(name, username, db, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["*"]

  mysql {
	  connection_url = "%s"
  }
}

resource "vault_database_secret_backend_static_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  username = "%s"
  rotation_period = 1800
  rotation_statements = ["SELECT 1;"]
}
`, path, db, connURL, name, username)
}
