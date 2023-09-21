// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDatabaseSecretBackendStaticRole_import(t *testing.T) {
	connURL := testutil.SkipTestEnvUnset(t, "MYSQL_URL")[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	username := acctest.RandomWithPrefix("user")
	dbName := acctest.RandomWithPrefix("db")
	name := acctest.RandomWithPrefix("staticrole")
	resourceName := "vault_database_secret_backend_static_role.test"

	if err := createTestUser(connURL, username); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_rotationPeriod(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "3600"),
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

func TestAccDatabaseSecretBackendStaticRole_rotationPeriod(t *testing.T) {
	connURL := testutil.SkipTestEnvUnset(t, "MYSQL_URL")[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	username := acctest.RandomWithPrefix("user")
	dbName := acctest.RandomWithPrefix("db")
	name := acctest.RandomWithPrefix("staticrole")
	resourceName := "vault_database_secret_backend_static_role.test"

	if err := createTestUser(connURL, username); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_rotationPeriod(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "3600"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_updatedRotationPeriod(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "1800"),
					resource.TestCheckResourceAttr(resourceName, "rotation_statements.0", "SELECT 1;"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendStaticRole_rotationSchedule(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	username := acctest.RandomWithPrefix("username")
	dbName := acctest.RandomWithPrefix("db")
	name := acctest.RandomWithPrefix("static-role")
	resourceName := "vault_database_secret_backend_static_role.test"

	if err := createTestUser(connURL, username); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_rotationSchedule(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_schedule", "* * * * *"),
					resource.TestCheckResourceAttr(resourceName, "rotation_window", "3600"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_updatedRotationSchedule(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_schedule", "*/30 * * * *"),
					resource.TestCheckResourceAttr(resourceName, "rotation_window", "14400"),
					resource.TestCheckResourceAttr(resourceName, "rotation_statements.0", "SELECT 1;"),
				),
			},
		},
	})
}

func testAccDatabaseSecretBackendStaticRoleCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_database_secret_backend_static_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("static role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func createTestUser(connURL, username string) error {
	mysqlURL := connURL
	runsInContainer := os.Getenv("RUNS_IN_CONTAINER") == "true"
	if !runsInContainer {
		mysqlURL = "root:mysql@tcp(localhost:3306)/"
	}

	ctx := context.Background()
	db, err := sql.Open("mysql", mysqlURL)
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

func testAccDatabaseSecretBackendStaticRoleConfig_rotationSchedule(name, username, db, path, connURL string) string {
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
  rotation_schedule = "* * * * *"
  rotation_window = 3600
  rotation_statements = ["ALTER USER '{{username}}'@'localhost' IDENTIFIED BY '{{password}}';"]
}
`, path, db, connURL, name, username)
}

func testAccDatabaseSecretBackendStaticRoleConfig_updatedRotationSchedule(name, username, db, path, connURL string) string {
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
  rotation_schedule = "*/30 * * * *"
  rotation_window = 14400
  rotation_statements = ["SELECT 1;"]
}
`, path, db, connURL, name, username)
}

func testAccDatabaseSecretBackendStaticRoleConfig_rotationPeriod(name, username, db, path, connURL string) string {
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

func testAccDatabaseSecretBackendStaticRoleConfig_updatedRotationPeriod(name, username, db, path, connURL string) string {
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
