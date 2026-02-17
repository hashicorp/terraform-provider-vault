// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccDBSecret tests password credential type with PostgreSQL
//
// This test verifies that the vault_database_secret ephemeral resource can
// successfully retrieve username and password credentials from Vault.
//
// Prerequisites:
// - PostgreSQL server running and accessible
// - Set POSTGRES_URL environment variable (e.g., "postgres://postgres:secret@localhost:5432/postgres?sslmode=disable")
//
// Uses the Echo Provider to test values set in ephemeral resources.
// See: https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccDBSecret(t *testing.T) {
	acctestutil.SkipTestAcc(t)
	mount := acctest.RandomWithPrefix("postgres")
	dbName := acctest.RandomWithPrefix("db")
	roleName := acctest.RandomWithPrefix("role")

	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	connURL := values[0]

	// catch-all regex to ensure all usernames and passwords are set to some value
	expectedUsernameRegex, err := regexp.Compile("^vault-(.+)-(\\w{20})$")
	expectedPasswordRegex, err := regexp.Compile("^\\S+$")
	if err != nil {
		t.Fatal(err)
	}
	templ := `{{ printf \"vault-%s-%s\" (.DisplayName) (random 20) }}`

	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() { acctestutil.TestAccPreCheck(t) },
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testDBSecretConfig(mount, dbName, roleName, connURL, templ, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_db", tfjsonpath.New("data").AtMapKey("username"), knownvalue.StringRegexp(expectedUsernameRegex)),
					statecheck.ExpectKnownValue("echo.test_db", tfjsonpath.New("data").AtMapKey("password"), knownvalue.StringRegexp(expectedPasswordRegex)),
				},
			},
		},
	})
}

// TestAccDBSecretRSAPrivateKey tests RSA private key credential type with Snowflake
//
// Snowflake is the database that supports RSA private key authentication in Vault.
// This test verifies that the vault_database_secret ephemeral resource can
// successfully retrieve RSA private key credentials from Vault's Snowflake database plugin.
//
// Prerequisites:
// - Snowflake account with API access
// - VAULT_TEST_USER must have SECURITYADMIN role or equivalent privileges to create users
// - Set environment variables:
//   - VAULT_ACC_TEST_SNOWFLAKE_URL: Snowflake connection URL
//     Format: "username@account.snowflakecomputing.com/database"
//     Example: "VAULT_TEST_USER@hashicorp-hashicorp_test.snowflakecomputing.com/TEST_DB"
//   - VAULT_ACC_TEST_SNOWFLAKE_PRIVATE_KEY: Path to Snowflake private key file (PEM format)
//     This is the private key for authenticating Vault to Snowflake (not the generated key)
//
// Note: Snowflake uses RSA key pairs for authentication. The VAULT_ACC_TEST_SNOWFLAKE_PRIVATE_KEY
// is used by Vault to connect to Snowflake, while the test verifies that Vault can generate new
// RSA key pairs for Snowflake users using Vault's internal key generation.
func TestAccDBSecretRSAPrivateKey(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	// Skip if Snowflake credentials are not provided
	values := testutil.SkipTestEnvUnset(t,
		"VAULT_ACC_TEST_SNOWFLAKE_URL",
		"VAULT_ACC_TEST_SNOWFLAKE_PRIVATE_KEY")
	if len(values) < 2 {
		t.Skip("Skipping RSA private key test: Required Snowflake environment variables not set. " +
			"Need VAULT_ACC_TEST_SNOWFLAKE_URL and VAULT_ACC_TEST_SNOWFLAKE_PRIVATE_KEY.")
	}

	mount := acctest.RandomWithPrefix("db-snowflake")
	dbName := acctest.RandomWithPrefix("db")
	roleName := acctest.RandomWithPrefix("role-rsa")

	// Parse VAULT_ACC_TEST_SNOWFLAKE_URL to extract username and connection URL
	// Expected format: "username@account.snowflakecomputing.com/database"
	fullURL := values[0]
	privateKeyPath := values[1]

	// Extract username from the URL (everything before the first @)
	atIndex := strings.Index(fullURL, "@")
	if atIndex == -1 {
		t.Fatal("VAULT_ACC_TEST_SNOWFLAKE_URL must be in format: username@account.snowflakecomputing.com/database")
	}
	username := fullURL[:atIndex]
	connURL := fullURL[atIndex+1:] // Everything after the @

	expectedUsernameRegex, err := regexp.Compile("^vault-(.+)-(\\w{20})$")
	// RSA private keys can be in PKCS#1 or PKCS#8 format
	expectedRSAKeyRegex, err := regexp.Compile("^-----BEGIN (RSA )?PRIVATE KEY-----")
	if err != nil {
		t.Fatal(err)
	}
	templ := `{{ printf \"vault-%s-%s\" (.DisplayName) (random 20) }}`

	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			// Skip on Vault < 1.20.0 due to Snowflake plugin bug (fixed in v0.13.0+)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion120)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testDBSecretConfigRSA(mount, dbName, roleName, connURL, username, templ, privateKeyPath),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_db", tfjsonpath.New("data").AtMapKey("username"), knownvalue.StringRegexp(expectedUsernameRegex)),
					statecheck.ExpectKnownValue("echo.test_db", tfjsonpath.New("data").AtMapKey("rsa_private_key"), knownvalue.StringRegexp(expectedRSAKeyRegex)),
				},
			},
		},
	})
}

// TestAccDBSecretClientCertificate tests client certificate credential type with MongoDB Atlas
//
// This test verifies that the vault_database_secret ephemeral resource can
// successfully retrieve client certificate credentials (certificate + private key)
// from Vault's MongoDB Atlas database plugin.
//
// Prerequisites:
// - MongoDB Atlas account with API access
// - Set environment variables:
//   - VAULT_ACC_TEST_MONGODB_ATLAS_PUBLIC_KEY: MongoDB Atlas public API key
//   - VAULT_ACC_TEST_MONGODB_ATLAS_PRIVATE_KEY: MongoDB Atlas private API key
//   - VAULT_ACC_TEST_MONGODB_ATLAS_PROJECT_ID: MongoDB Atlas project ID
//   - VAULT_ACC_TEST_CA_CERT: Path to CA certificate file for certificate generation
//   - VAULT_ACC_TEST_CA_KEY: Path to CA private key file for certificate generation
//
// Note: MongoDB Atlas uses X.509 certificates for authentication, where the username
// is derived from the certificate's Common Name (CN).
func TestAccDBSecretClientCertificate(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	// Skip if MongoDB Atlas credentials are not provided
	values := testutil.SkipTestEnvUnset(t,
		"VAULT_ACC_TEST_MONGODB_ATLAS_PUBLIC_KEY",
		"VAULT_ACC_TEST_MONGODB_ATLAS_PRIVATE_KEY",
		"VAULT_ACC_TEST_MONGODB_ATLAS_PROJECT_ID",
		"VAULT_ACC_TEST_CA_CERT",
		"VAULT_ACC_TEST_CA_KEY",
	)
	if len(values) < 5 {
		t.Skip("Skipping client certificate test: Required MongoDB Atlas environment variables not set. " +
			"This test requires VAULT_ACC_TEST_MONGODB_ATLAS_PUBLIC_KEY, VAULT_ACC_TEST_MONGODB_ATLAS_PRIVATE_KEY, " +
			"VAULT_ACC_TEST_MONGODB_ATLAS_PROJECT_ID, VAULT_ACC_TEST_CA_CERT, and VAULT_ACC_TEST_CA_KEY.")
	}

	mount := acctest.RandomWithPrefix("db-cert")
	dbName := acctest.RandomWithPrefix("db")
	roleName := acctest.RandomWithPrefix("role-cert")
	publicKey := values[0]
	privateKey := values[1]
	projectID := values[2]
	caCert := values[3]
	caKey := values[4]

	// MongoDB Atlas uses CN (Common Name) format for usernames with client certificates
	expectedUsernameRegex, err := regexp.Compile("^CN=")
	expectedCertRegex, err := regexp.Compile("^-----BEGIN CERTIFICATE-----")
	expectedKeyRegex, err := regexp.Compile("^-----BEGIN")
	if err != nil {
		t.Fatal(err)
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testDBSecretConfigClientCert(mount, dbName, roleName, publicKey, privateKey, projectID, caCert, caKey),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_db", tfjsonpath.New("data").AtMapKey("username"), knownvalue.StringRegexp(expectedUsernameRegex)),
					statecheck.ExpectKnownValue("echo.test_db", tfjsonpath.New("data").AtMapKey("client_certificate"), knownvalue.StringRegexp(expectedCertRegex)),
					statecheck.ExpectKnownValue("echo.test_db", tfjsonpath.New("data").AtMapKey("private_key"), knownvalue.StringRegexp(expectedKeyRegex)),
					statecheck.ExpectKnownValue("echo.test_db", tfjsonpath.New("data").AtMapKey("private_key_type"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testDBSecretConfig(mount, dbName, roleName, connUrl, templ, credentialType string) string {
	credentialTypeConfig := ""
	if credentialType != "" && credentialType != "password" {
		credentialTypeConfig = fmt.Sprintf(`
  credential_type = "%s"`, credentialType)
	}

	return fmt.Sprintf(`
resource "vault_database_secrets_mount" "test" {
  path = "%s"

  postgresql {
    name              = "%s"
    connection_url    = "%s"
    allowed_roles     = ["*"]
    username_template = "%s"
  }
}

resource "vault_database_secret_backend_role" "role" {
  backend             = vault_database_secrets_mount.test.path
  name                = "%s"
  db_name             = vault_database_secrets_mount.test.postgresql.0.name
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
  ]%s
}

ephemeral "vault_database_secret" "db_secret" {
	mount    = vault_database_secrets_mount.test.path
	mount_id = vault_database_secrets_mount.test.id
	name     = vault_database_secret_backend_role.role.name
}

provider "echo" {
	data = ephemeral.vault_database_secret.db_secret
}

resource "echo" "test_db" {}
`, mount, dbName, connUrl, templ, roleName, credentialTypeConfig)
}

func testDBSecretConfigRSA(mount, dbName, roleName, connUrl, username, templ, privateKeyPath string) string {
	return fmt.Sprintf(`
resource "vault_database_secrets_mount" "test" {
  path = "%s"

  snowflake {
    name                     = "%s"
    connection_url           = "%s"
    username                 = "%s"
    allowed_roles            = ["*"]
    username_template        = "%s"
    private_key_wo           = file("%s")
    private_key_wo_version   = "1"
  }
}

resource "vault_database_secret_backend_role" "role" {
  backend             = vault_database_secrets_mount.test.path
  name                = "%s"
  db_name             = vault_database_secrets_mount.test.snowflake.0.name
  credential_type     = "rsa_private_key"

  creation_statements = [
    "CREATE USER IF NOT EXISTS \"{{name}}\";",
    "ALTER USER \"{{name}}\" SET RSA_PUBLIC_KEY='{{public_key}}';"
  ]
  revocation_statements = [
    "DROP USER IF EXISTS \"{{name}}\";"
  ]
  default_ttl = 300
  max_ttl = 600
}

ephemeral "vault_database_secret" "db_secret" {
	mount    = vault_database_secrets_mount.test.path
	mount_id = vault_database_secrets_mount.test.id
	name     = vault_database_secret_backend_role.role.name
}

provider "echo" {
	data = ephemeral.vault_database_secret.db_secret
}

resource "echo" "test_db" {}
`, mount, dbName, connUrl, username, templ, privateKeyPath, roleName)
}

func testDBSecretConfigClientCert(mount, dbName, roleName, publicKey, privateKey, projectID, caCert, caKey string) string {
	return fmt.Sprintf(`
resource "vault_database_secrets_mount" "test" {
  path = "%s"

  mongodbatlas {
    name          = "%s"
    private_key   = "%s"
    public_key    = "%s"
    project_id    = "%s"
    allowed_roles = ["*"]
  }
}

resource "vault_database_secret_backend_role" "role" {
  backend             = vault_database_secrets_mount.test.path
  name                = "%s"
  db_name             = vault_database_secrets_mount.test.mongodbatlas[0].name
  default_ttl         = 1800
  max_ttl             = 3600
  creation_statements = [jsonencode({
    database_name : "$external",
    x509Type : "CUSTOMER",
    roles : [{ databaseName : "sample_training", roleName : "readWrite" }]
  })]
  credential_type = "client_certificate"
  credential_config = {
    ca_cert = file("%s")
    ca_private_key = file("%s")
    key_type = "rsa"
    key_bits = "2048"
    signature_bits = "256"
    common_name_template = "{{.RoleName}}_{{unix_time}}"
  }
}

ephemeral "vault_database_secret" "db_secret" {
	mount    = vault_database_secrets_mount.test.path
	mount_id = vault_database_secrets_mount.test.id
	name     = vault_database_secret_backend_role.role.name
}

provider "echo" {
	data = ephemeral.vault_database_secret.db_secret
}

resource "echo" "test_db" {}
`, mount, dbName, privateKey, publicKey, projectID, roleName, caCert, caKey)
}
