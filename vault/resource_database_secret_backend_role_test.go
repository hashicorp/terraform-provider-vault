// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDatabaseSecretBackendRole_import(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	dbName := acctest.RandomWithPrefix("db")
	name := acctest.RandomWithPrefix("role")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.ca_cert", "cert"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.ca_private_key", "key"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.key_type", "rsa"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.key_bits", "2048"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.signature_bits", "256"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.common_name_template", "{{.DisplayName}}_{{.RoleName}}"),
				),
			},
			{
				ResourceName:            "vault_database_secret_backend_role.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"key_bits", "signature_bits"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendRole_basic(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("role")
	dbName := acctest.RandomWithPrefix("db")
	testConf := testAccDatabaseSecretBackendRoleConfig_basic(name, dbName, backend, connURL)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.ca_cert", "caCert"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.ca_private_key", "privateKey"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.key_type", "ec"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.key_bits", "224"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.signature_bits", "384"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_role.role", "credential_config.common_name_template", "{{.DisplayName}}_{{.RoleName}}_{{unix_time}}"),
				),
			},
			testutil.GetImportTestStep("vault_database_secret_backend_role.role", false, nil, "key_bits", "signature_bits"),
		},
	})
}

func testAccDatabaseSecretBackendRoleCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_database_secret_backend_role" {
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
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]

  mysql {
	  connection_url = "%s"
  }
}

resource "vault_database_secret_backend_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  default_ttl = 3600
  max_ttl = 7200
  creation_statements = ["SELECT 1;"]
}

resource "vault_database_secret_backend_role" "role" {
  backend             = vault_mount.db.path
  name                = "dev"
  db_name             = vault_database_secret_backend_connection.test.name
  creation_statements = ["{'database_name': '$external', 'x509Type': 'CUSTOMER', 'roles': [{'databaseName':'dbName','roleName':'read'}]}"]
  credential_config = {
    ca_cert = "cert"
    ca_private_key = "key"
	key_type = "rsa"
	key_bits = "2048"
	signature_bits = "256"
	common_name_template = "{{.DisplayName}}_{{.RoleName}}"
  }
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
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]

  mysql {
	  connection_url = "%s"
  }
}

resource "vault_database_secret_backend_role" "test" {
  backend = vault_mount.db.path
  db_name = vault_database_secret_backend_connection.test.name
  name = "%s"
  default_ttl = 1800
  max_ttl = 3600
  creation_statements = ["SELECT 1;"]
}

resource "vault_database_secret_backend_role" "role" {
  backend             = vault_mount.db.path
  name                = "dev"
  db_name             = vault_database_secret_backend_connection.test.name
  creation_statements = ["{'database_name': '$external', 'x509Type': 'CUSTOMER', 'roles': [{'databaseName':'dbName','roleName':'readWrite'}]}"]
  credential_config = {
    ca_cert = "caCert"
    ca_private_key = "privateKey"
	key_type = "ec"
	key_bits = "224"
	signature_bits = "384"
	common_name_template = "{{.DisplayName}}_{{.RoleName}}_{{unix_time}}"
  }
}
`, path, db, connURL, name)
}
