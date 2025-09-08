// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDatabaseSecretBackendRole_basic(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("role")
	dbName := acctest.RandomWithPrefix("db")
	resourceName := "vault_database_secret_backend_role.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendRoleConfig_basic(name, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "default_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "7200"),
					resource.TestCheckResourceAttr(resourceName, "creation_statements.0", "SELECT 1;"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendRoleConfig_updated(name, dbName, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "default_ttl", "1800"),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "creation_statements.0", "SELECT 1;"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
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
// by generating the API keys under your MongoDB Atlas Organization
func TestAccDatabaseSecretBackendRole_ClientCertificate(t *testing.T) {
	privateKey, publicKey := testutil.GetTestMDBACreds(t)
	projectID := testutil.SkipTestEnvUnset(t, "MONGODB_ATLAS_PROJECT_ID")[0]
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("role")
	dbName := acctest.RandomWithPrefix("db")
	caCert := testutil.SkipTestEnvUnset(t, "MONGODB_ATLAS_CA_CERT")[0]
	caKey := testutil.SkipTestEnvUnset(t, "MONGODB_ATLAS_CA_KEY")[0]

	resourceName := "vault_database_secret_backend_role.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendRoleConfig_ClientCertificate(name, dbName, backend, privateKey, publicKey, projectID,
					caCert,
					caKey,
					"rsa",
					"2048",
					"256",
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "default_ttl", "1800"),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.key_type", "rsa"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.key_bits", "2048"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.signature_bits", "256"),
					resource.TestCheckResourceAttrSet(resourceName, "credential_config.ca_cert"),
					resource.TestCheckResourceAttrSet(resourceName, "credential_config.ca_private_key"),
					resource.TestCheckResourceAttr(resourceName, "credential_config.common_name_template", "{{.DisplayName}}_{{.RoleName}}"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendRoleConfig_ClientCertificate(name, dbName, backend, privateKey, publicKey, projectID,
					caCert,
					caKey,
					"ec",
					"224",
					"384",
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "db_name", dbName),
					resource.TestCheckResourceAttr(resourceName, "default_ttl", "1800"),
					resource.TestCheckResourceAttr(resourceName, "max_ttl", "3600"),
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
`, path, db, connURL, name)
}

func testAccDatabaseSecretBackendRoleConfig_ClientCertificate(name, db, path, privateKey, publicKey, projectID string,
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
  allowed_roles = ["dev"]

  mongodbatlas {
    private_key = "%s"
    public_key  = "%s"
    project_id  = "%s"
  }
}

resource "vault_database_secret_backend_role" "test" {
  backend             = vault_mount.db.path
  name                = "%s"
  db_name             = vault_database_secret_backend_connection.test.name
  default_ttl         = 1800
  max_ttl             = 3600
  creation_statements = [jsonencode(
    {
      database_name : "$external",
      x509Type : "CUSTOMER",
      roles : [{ databaseName : "sample_training", roleName : "readWrite" }]
  })]
  credential_type = "client_certificate"
  credential_config = {
    ca_cert = file("%s")
    ca_private_key = file("%s")
	key_type = "%s"
	key_bits = "%s"
	signature_bits = "%s"
	common_name_template = "{{.DisplayName}}_{{.RoleName}}"
  }
}
`, path, db, privateKey, publicKey, projectID, name, caCert, caKey, keyType, keyBits, signatureBits)
}
