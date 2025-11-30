// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"

	_ "github.com/go-sql-driver/mysql"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	_ "github.com/sijms/go-ora/v2"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendStaticRoleCheckDestroy,
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

func TestAccDatabaseSecretBackendStaticRole_credentialType(t *testing.T) {
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_credentialType(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "credential_type", "password"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendStaticRole_credentialConfig(t *testing.T) {
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_credentialConfig(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "credential_config.password_policy", "numeric"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_updatedCredentialConfig(name, username, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "credential_config.password_policy", "alphanumeric"),
				),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendStaticRoleCheckDestroy,
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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

// TestAccDatabaseSecretBackendStaticRole_Rootless tests the
// Rootless Config and Rotation flow for Static Roles.
//
// To run locally you will need to set the following env vars:
//   - POSTGRES_URL_TEST
//   - POSTGRES_URL_ROOTLESS
//
// See .github/workflows/build.yml for details.
func TestAccDatabaseSecretBackendStaticRole_Rootless(t *testing.T) {
	connURLTestRoot := testutil.SkipTestEnvUnset(t, "POSTGRES_URL_TEST")[0]
	connURL := testutil.SkipTestEnvUnset(t, "POSTGRES_URL_ROOTLESS")[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	username := acctest.RandomWithPrefix("user")
	dbName := acctest.RandomWithPrefix("db")
	name := acctest.RandomWithPrefix("staticrole")
	resourceName := "vault_database_secret_backend_static_role.test"

	// create static database user
	testutil.CreateTestPGUser(t, connURLTestRoot, username, "testpassword", testRoleStaticCreate)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_rootlessConfig(name, username, dbName, backend, connURL, "testpassword"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "3600"),
				),
			},
			{
				ResourceName:            "vault_database_secret_backend_static_role.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldSelfManagedPassword},
			},
		},
	})
}

// TestAccDatabaseSecretBackendStaticRole_SkipImportRotation tests the skip
// auto import Rotation configuration.
//
// To run locally you will need to set the following env vars:
//   - POSTGRES_URL
//   - POSTGRES_URL_TEST
//
// See .github/workflows/build.yml for details.
func TestAccDatabaseSecretBackendStaticRole_SkipImportRotation(t *testing.T) {
	connURLTestRoot := testutil.SkipTestEnvUnset(t, "POSTGRES_URL_TEST")[0]
	connURL := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")[0]

	parsedURL, err := url.Parse(connURLTestRoot)
	if err != nil {
		t.Fatal(err)
	}

	vaultAdminUser := parsedURL.User.Username()

	backend := acctest.RandomWithPrefix("tf-test-db")
	staticUsername := acctest.RandomWithPrefix("user")
	dbName := acctest.RandomWithPrefix("db")
	roleName := acctest.RandomWithPrefix("staticrole")
	resourceName := "vault_database_secret_backend_static_role.test"

	// create static database user
	testutil.CreateTestPGUser(t, connURLTestRoot, staticUsername, "testpassword", testRoleStaticCreate)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_skipImportRotation(roleName, staticUsername, dbName, backend, connURL, vaultAdminUser),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "username", staticUsername),
					resource.TestCheckResourceAttr(resourceName, "skip_import_rotation", "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, ""),
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

func createOracleTestUser(connURL, username, password string) error {
	ctx := context.Background()
	db, err := sql.Open("oracle", connURL)
	if err != nil {
		return fmt.Errorf("failed to open Oracle connection: %w", err)
	}
	defer db.Close()

	// Test the connection
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping Oracle: %w", err)
	}

	// Drop user if exists (cleanup from previous runs)
	_, _ = db.ExecContext(ctx, "DROP USER "+username+" CASCADE")
	// Create user
	createSQL := "CREATE USER " + username + " IDENTIFIED BY " + password + " ACCOUNT UNLOCK"
	_, err = db.ExecContext(ctx, createSQL)
	if err != nil {
		return fmt.Errorf("failed to create Oracle user (SQL: %s): %w", createSQL, err)
	}

	// Grant comprehensive privileges
	grants := []string{
		"GRANT CREATE USER TO " + username + " WITH ADMIN OPTION",
		"GRANT ALTER USER TO " + username + " WITH ADMIN OPTION",
		"GRANT DROP USER TO " + username + " WITH ADMIN OPTION",
		"GRANT CONNECT TO " + username + " WITH ADMIN OPTION",
		"GRANT CREATE SESSION TO " + username + " WITH ADMIN OPTION",
		"GRANT RESOURCE TO " + username,
		"GRANT ALTER SYSTEM TO " + username + " WITH ADMIN OPTION",
	}

	for _, grant := range grants {
		if _, err := db.ExecContext(ctx, grant); err != nil {
			return fmt.Errorf("failed to execute grant %q: %w", grant, err)
		}
	}

	return nil
}

// TestAccDatabaseSecretBackendStaticRole_OracleSelfManaged tests the
// self-managed configuration for Oracle Static Roles in the CI pipeline.
//
// This test is designed to run in the CI environment where Oracle is
// accessible via ORACLE_URL_TEST.
//
// To run locally in the CI pipeline you will need to set:
//   - ORACLE_URL_TEST: Direct Oracle connection URL
//
// See .github/workflows/build.yml for details.
func TestAccDatabaseSecretBackendStaticRole_OracleSelfManaged(t *testing.T) {
	connURLTest := os.Getenv("ORACLE_URL_TEST")
	if connURLTest == "" {
		t.Skip("ORACLE_URL_TEST not set")
	}

	backend := acctest.RandomWithPrefix("tf-test-db")
	user := acctest.RandomWithPrefix("USR")
	password := "StaticUserPass123"
	dbName := acctest.RandomWithPrefix("db")
	name := acctest.RandomWithPrefix("staticrole")
	resourceName := "vault_database_secret_backend_static_role.test"

	// Try to create static database user, but allow test to continue if it fails
	username := strings.ReplaceAll(user, "-", "_")
	if err := createOracleTestUser(connURLTest, username, password); err != nil {
		t.Logf("Warning: Failed to create Oracle user (might already exist): %v", err)
	}

	testProvider := Provider()
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_oracleSelfManaged(name, username, dbName, backend, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "3600"),
				),
			},
			{
				ResourceName:            "vault_database_secret_backend_static_role.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldSelfManagedPassword},
			},
		},
	})
}

// TestAccDatabaseSecretBackendStaticRole_OraclePasswordWO tests the
// password_wo (write-only password) field for Oracle Static Roles in the CI pipeline.
//
// This test is designed to run in the CI environment where Oracle is
// accessible via ORACLE_URL_TEST.
//
// To run locally in the CI pipeline you will need to set:
//   - ORACLE_URL_TEST: Direct Oracle connection URL
//
// See .github/workflows/build.yml for details.
func TestAccDatabaseSecretBackendStaticRole_OraclePasswordWO(t *testing.T) {
	connURLTest := os.Getenv("ORACLE_URL_TEST")
	if connURLTest == "" {
		t.Skip("ORACLE_URL_TEST not set")
	}

	backend := acctest.RandomWithPrefix("tf-test-db")
	username1 := acctest.RandomWithPrefix("USR")
	username2 := acctest.RandomWithPrefix("USR")
	password1 := "TestPass123"
	password2 := "TestPass456"
	dbName := acctest.RandomWithPrefix("db")
	name := acctest.RandomWithPrefix("staticrole")
	resourceName := "vault_database_secret_backend_static_role.test"

	// Try to create static database users
	if err := createOracleTestUser(connURLTest, username1, password1); err != nil {
		t.Logf("Warning: Failed to create Oracle user %s: %v", username1, err)
	}
	if err := createOracleTestUser(connURLTest, username2, password2); err != nil {
		t.Logf("Warning: Failed to create Oracle user %s: %v", username2, err)
	}

	testProvider := Provider()
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			// Step 1: Create with password_wo and skip_import_rotation=false (default)
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_oraclePasswordWO(name, username1, dbName, backend, password1, false, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username1),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "3600"),
					resource.TestCheckResourceAttr(resourceName, "skip_import_rotation", "false"),
					resource.TestCheckResourceAttr(resourceName, "password_wo_version", "1"),
				),
			},
			// Step 2: Update to different user with skip_import_rotation=true
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_oraclePasswordWO(name, username2, dbName, backend, password2, true, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username2),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "3600"),
					resource.TestCheckResourceAttr(resourceName, "skip_import_rotation", "true"),
					resource.TestCheckResourceAttr(resourceName, "password_wo_version", "2"),
				),
			},
			// Step 3: Import test
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldPasswordWO},
			},
		},
	})
}

func testAccDatabaseSecretBackendStaticRoleConfig_credentialType(name, username, db, path, connURL string) string {
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
  credential_type = "password"
  rotation_period = 1800
  rotation_statements = ["ALTER USER '{{username}}'@'localhost' IDENTIFIED BY '{{password}}';"]
}
`, path, db, connURL, name, username)
}

func testAccDatabaseSecretBackendStaticRoleConfig_credentialConfig(name, username, db, path, connURL string) string {
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

resource "vault_password_policy" "test" {
  name = "numeric"

  policy = <<EOT
    length = 20
    rule "charset" {
      charset = "0123456789"
    }
  EOT
}

resource "vault_database_secret_backend_static_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  username = "%s"
  credential_type = "password"
  credential_config = { "password_policy" = "numeric" }
  rotation_period = 1800
  rotation_statements = ["ALTER USER '{{username}}'@'localhost' IDENTIFIED BY '{{password}}';"]
}
`, path, db, connURL, name, username)
}

func testAccDatabaseSecretBackendStaticRoleConfig_updatedCredentialConfig(name, username, db, path, connURL string) string {
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

resource "vault_password_policy" "test" {
  name = "alphanumeric"

  policy = <<EOT
    length = 20
    rule "charset" {
      charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    }
  EOT
}

resource "vault_database_secret_backend_static_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  username = "%s"
  credential_type = "password"
  credential_config = { "password_policy" = "alphanumeric" }
  rotation_period = 1800
  rotation_statements = ["ALTER USER '{{username}}'@'localhost' IDENTIFIED BY '{{password}}';"]
}
`, path, db, connURL, name, username)
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

func testAccDatabaseSecretBackendStaticRoleConfig_skipImportRotation(roleName, staticUsername, db, path, connURL, vaultAdminUser string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["*"]

  postgresql {
	connection_url = "%s"
	username = "%s"
  }
}

resource "vault_database_secret_backend_static_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  username = "%s"
  skip_import_rotation = true
  rotation_period = 3600
}
`, path, db, connURL, vaultAdminUser, roleName, staticUsername)
}

func testAccDatabaseSecretBackendStaticRoleConfig_rootlessConfig(name, username, db, path, connURL, smPassword string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["*"]

  postgresql {
	  connection_url = "%s"
      self_managed   = true
  }
}

resource "vault_database_secret_backend_static_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  username = "%s"
  self_managed_password = "%s"
  rotation_period = 3600
}
`, path, db, connURL, name, username, smPassword)
}

func testAccDatabaseSecretBackendStaticRoleConfig_oracleSelfManaged(name, username, db, path, smPassword string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["*"]

  oracle {
    connection_url = "{{username}}/{{password}}@//oracle:1521/XEPDB1"
    self_managed   = true
    plugin_name    = "vault-plugin-database-oracle"
  }
}

resource "vault_database_secret_backend_static_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  username = "%s"
  self_managed_password = "%s"
  rotation_period = 3600
}
`, path, db, name, username, smPassword)
}

func testAccDatabaseSecretBackendStaticRoleConfig_oraclePasswordWO(name, username, db, path, password string, skipImportRotation bool, version int) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["*"]

  oracle {
    connection_url = "{{username}}/{{password}}@//oracle:1521/XEPDB1"
    self_managed   = true
    plugin_name    = "vault-plugin-database-oracle"
  }
}

resource "vault_database_secret_backend_static_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  username = "%s"
  password_wo = "%s"
  password_wo_version = %d
  skip_import_rotation = %t
  rotation_period = 3600
}
`, path, db, name, username, password, version, skipImportRotation)
}

var testRoleStaticCreate = `
CREATE ROLE "{{name}}" WITH
  LOGIN
  PASSWORD '{{password}}';
`
