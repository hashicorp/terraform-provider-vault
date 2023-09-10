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

// Prior running basic tests:
// 1. docker-compose up -d vault mysql
// 2. source .test-env
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
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "credential_type", "password"),
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
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "credential_type", "password"),
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_static_role.test", "credential_type", "password"),
				),
			},
		},
	})
}

// This test requires some prior setup using a configured
// MongoDB Atlas account, making it a local-only test
// Below are the environment variables required to run this test
//  1. MONGODB_ATLAS_PRIVATE_KEY:
//     The Private Programmatic API Key used to connect with MongoDB Atlas API.
//  2. MONGODB_ATLAS_PUBLIC_KEY:
//     The Public Programmatic API Key used to authenticate with the MongoDB Atlas API.
//  3. MONGODB_ATLAS_PROJECT_ID:
//     The Project ID the Database User should be created within.
//  4. MONGODB_ATLAS_CA_CERT:
//     Path to the PEM-encoded CA certificate.
//  5. MONGODB_ATLAS_CA_KEY:
//     Path to the PEM-encoded private key for the CA cert.
//
// The above variables can be obtained via the MongoDB Atlas Portal
// by generating the API keys under your MongoDB Atlas Organization.
// The CA certs you should generate by yourself with openssl. Then configure
// MongoDB Atlas "Self-managed X.509 Authentication" in Security -> Advanced
func TestAccDatabaseSecretBackendStaticRole_ClientCertificate(t *testing.T) {
	privateKey, publicKey := testutil.GetTestMDBACreds(t)
	projectID := testutil.SkipTestEnvUnset(t, "MONGODB_ATLAS_PROJECT_ID")[0]
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("staticrole")
	username := acctest.RandomWithPrefix("user")
	dbName := acctest.RandomWithPrefix("db")
	caCert := testutil.SkipTestEnvUnset(t, "MONGODB_ATLAS_CA_CERT")[0]
	caKey := testutil.SkipTestEnvUnset(t, "MONGODB_ATLAS_CA_KEY")[0]

	resourceName := "vault_database_secret_backend_static_role.test"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendStaticRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_ClientCertificate(name, username, dbName, backend, privateKey, publicKey, projectID,
					caCert,
					caKey,
					"rsa",
					"2048",
					"256",
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "3600"),
					resource.TestCheckResourceAttr(resourceName, "credential_type", "client_certificate"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.key_type", "rsa"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.key_bits", "2048"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.signature_bits", "256"),
					resource.TestCheckResourceAttrSet(resourceName, "credential_config.ca_cert"),
					resource.TestCheckResourceAttrSet(resourceName, "credential_config.ca_private_key"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.common_name_template", "{{.DisplayName}}_{{.RoleName}}"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendStaticRoleConfig_ClientCertificate(name, username, dbName, backend, privateKey, publicKey, projectID,
					caCert,
					caKey,
					"ec",
					"224",
					"384",
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "3600"),
					resource.TestCheckResourceAttr(resourceName, "credential_type", "client_certificate"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.key_bits", "224"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.signature_bits", "384"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.common_name_template", "{{.DisplayName}}_{{.RoleName}}"),
					resource.TestCheckResourceAttrSet(resourceName, "credential_config.ca_cert"),
					resource.TestCheckResourceAttrSet(resourceName, "credential_config.ca_private_key"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
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
			return fmt.Errorf("sttatic role %q still exists", rs.Primary.ID)
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

func testAccDatabaseSecretBackendStaticRoleConfig_ClientCertificate(name, username, db, path, privateKey, publicKey, projectID string,
	caCert, caKey, keyType, keyBits, signatureBits string,
) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend       = vault_mount.db.path
  name          = "%s"
  allowed_roles = ["*"]

  mongodbatlas {
    private_key = "%s"
    public_key  = "%s"
    project_id  = "%s"
  }
}

resource "vault_database_secret_backend_static_role" "test" {
  backend             = vault_mount.db.path
  name                = "%s"
  username            = "%s"
  db_name             = vault_database_secret_backend_connection.test.name
  rotation_period     = 3600
  credential_type     = "client_certificate"
  credential_config = {
    ca_cert = file("%s")
    ca_private_key = file("%s")
	key_type = "%s"
	key_bits = "%s"
	signature_bits = "%s"
	common_name_template = "{{.DisplayName}}_{{.RoleName}}"
  }
}
`, path, db, privateKey, publicKey, projectID, name, username, caCert, caKey, keyType, keyBits, signatureBits)
}
