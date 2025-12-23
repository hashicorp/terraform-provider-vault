// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDatabaseSecretsMount_mssql(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMSSQL)

	cleanupFunc, connURL := testutil.PrepareMSSQLTestContainer(t)

	t.Cleanup(cleanupFunc)

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineMSSQL.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	name2 := name + "-2"

	parsedURL, err := url.Parse(connURL)
	if err != nil {
		t.Fatal(err)
	}

	importIgnoreKeys := []string{
		"engine_count",
		"mssql.0.verify_connection",
		"mssql.0.password",
		"mssql.0.connection_url",
	}
	resourceType := "vault_database_secrets_mount"
	resourceName := resourceType + ".db"

	username := parsedURL.User.Username()
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeDatabase, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretsMount_mssql(name, backend, pluginName, parsedURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mssql.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.username", username),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.name", name),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.contained_db", "false"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importIgnoreKeys,
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					resp, err := client.Logical().Read(fmt.Sprintf("%s/creds/%s", backend, "dev"))
					if err != nil {
						t.Fatal(err)
					}
					if resp == nil {
						t.Fatal("empty response")
					}
				},
				Config: testAccDatabaseSecretsMount_mssql(name2, backend, pluginName, parsedURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mssql.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.username", username),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.name", name2),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.contained_db", "false"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importIgnoreKeys,
			},
		},
	})
}

func TestAccDatabaseSecretsMount_mssql_multi(t *testing.T) {
	testutil.SkipTestEnvSet(t, "SKIP_MSSQL_MULTI_CI")
	MaybeSkipDBTests(t, dbEngineMSSQL)

	cleanupFunc, connURL := testutil.PrepareMSSQLTestContainer(t)
	t.Cleanup(cleanupFunc)

	cleanupFunc2, connURL2 := testutil.PrepareMSSQLTestContainer(t)
	t.Cleanup(cleanupFunc2)

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineMSSQL.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	name2 := acctest.RandomWithPrefix("db2")

	parsedURL, err := url.Parse(connURL)
	if err != nil {
		t.Fatal(err)
	}

	parsedURL2, err := url.Parse(connURL2)
	if err != nil {
		t.Fatal(err)
	}

	importIgnoreKeys := []string{
		"engine_count",
		"mssql.0.verify_connection",
		"mssql.0.password",
		"mssql.0.connection_url",
		"mssql.1.verify_connection",
		"mssql.1.password",
		"mssql.1.connection_url",
	}

	resourceType := "vault_database_secrets_mount"
	resourceName := resourceType + ".db"
	username := parsedURL.User.Username()
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeDatabase, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretsMount_mssql_dual(name, name2, backend, pluginName, parsedURL, parsedURL2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mssql.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.0", "dev1"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.username", username),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.contained_db", "false"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.allowed_roles.0", "dev2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.connection_url", connURL2),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.max_open_connections", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.username", username),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.contained_db", "false"),
				),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					for _, role := range []string{"dev1", "dev2"} {
						resp, err := client.Logical().Read(fmt.Sprintf("%s/creds/%s", backend, role))
						if err != nil {
							t.Fatal(err)
						}
						if resp == nil {
							t.Fatal("empty response")
						}
					}
				},
				Config: testAccDatabaseSecretsMount_mssql_dual(name, name2, backend, pluginName, parsedURL, parsedURL2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mssql.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.0", "dev1"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.username", username),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.contained_db", "false"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.allowed_roles.0", "dev2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.connection_url", connURL2),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.max_open_connections", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.username", username),
					resource.TestCheckResourceAttr(resourceName, "mssql.1.contained_db", "false"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importIgnoreKeys,
			},
			{
				Config: testAccDatabaseSecretsMount_mssql(name, backend, pluginName, parsedURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mssql.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.username", username),
					resource.TestCheckResourceAttr(resourceName, "mssql.0.contained_db", "false"),
				),
			},
		},
	})
}

// TestAccDatabaseSecretsMount_postgresql_automatedRootRotation tests that Automated
// Root Rotation parameters are compatible with the DB Secrets Mount resource
// Note: update steps are not included since DB mounts can only be configured once
func TestAccDatabaseSecretsMount_postgresql_automatedRootRotation(t *testing.T) {
	MaybeSkipDBTests(t, dbEnginePostgres)

	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	resourceName := "vault_database_secrets_mount.test"
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretsMount_postgres_automatedRootRotation(name, backend, connURL, "", 10, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "postgresql.0.rotation_period", "10"),
					resource.TestCheckResourceAttr(resourceName, "postgresql.0.rotation_window", "0"),
					resource.TestCheckResourceAttr(resourceName, "postgresql.0.rotation_schedule", ""),
					resource.TestCheckResourceAttr(resourceName, "postgresql.0.disable_automated_rotation", "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				"engine_count", "postgresql.0.connection_url", "postgresql.0.verify_connection"),
		},
	})
}

func TestAccDatabaseSecretsMount_hana(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineHana)

	values := testutil.SkipTestEnvUnset(t, "HANA_CONNECTION_URL")
	connURL := values[0]

	username := os.Getenv("HANA_USERNAME")
	password := os.Getenv("HANA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineHana.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	userTempl := "{{.DisplayName}}_{{random 8}}"

	importIgnoreKeys := []string{
		"engine_count",
		"hana.0.verify_connection",
		"hana.0.password",
		"hana.0.connection_url",
	}
	resourceType := "vault_database_secrets_mount"
	resourceName := resourceType + ".db"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeDatabase, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretsMount_hana(name, backend, pluginName, connURL, username, password, userTempl),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "hana.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "hana.0.allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "hana.0.allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "hana.0.allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(resourceName, "hana.0.connection_url", connURL),
					resource.TestCheckResourceAttr(resourceName, "hana.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(resourceName, "hana.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(resourceName, "hana.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(resourceName, "hana.0.username", username),
					resource.TestCheckResourceAttr(resourceName, "hana.0.name", name),
					resource.TestCheckResourceAttr(resourceName, "hana.0.disable_escaping", "true"),
					resource.TestCheckResourceAttr(resourceName, "hana.0.username_template", userTempl),
					func(s *terraform.State) error {
						client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

						// Validate that the mount can generate credentials through the role
						resp, err := client.Logical().Read(fmt.Sprintf("%s/creds/%s", backend, "dev"))
						if err != nil {
							return fmt.Errorf("error reading credentials: %v", err)
						}
						if resp == nil {
							return fmt.Errorf("no credentials returned")
						}
						if resp.Data["username"] == nil || resp.Data["password"] == nil {
							return fmt.Errorf("credentials missing username or password")
						}

						// Verify the generated username matches the template pattern
						generatedUsername := resp.Data["username"].(string)
						if !strings.Contains(generatedUsername, "TOKEN_TERRAFORM_") {
							return fmt.Errorf("generated username %q does not match template pattern (expected format: <displayname>_<random>)", generatedUsername)
						}

						return nil
					},
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importIgnoreKeys,
			},
		},
	})
}

func testAccDatabaseSecretsMount_mssql(name, path, pluginName string, parsedURL *url.URL) string {
	password, _ := parsedURL.User.Password()

	config := `
  mssql {
    allowed_roles     = ["dev", "prod"]
    plugin_name       = "%s"
    name              = "%s"
    connection_url    = "%s"
	username          = "%s"
	password          = "%s"
    verify_connection = true
  }`

	result := fmt.Sprintf(`
resource "vault_database_secrets_mount" "db" {
  path = "%s"
%s
}

resource "vault_database_secret_backend_role" "test" {
  backend = vault_database_secrets_mount.db.path
  name    = "dev"
  db_name = vault_database_secrets_mount.db.mssql[0].name
  creation_statements = [
    "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';",
    "CREATE USER [{{name}}] FOR LOGIN [{{name}}];",
    "GRANT SELECT ON SCHEMA::dbo TO [{{name}}];",
  ]
}
`, path, fmt.Sprintf(config, pluginName, name, parsedURL.String(), parsedURL.User.Username(), password))

	return result
}

func testAccDatabaseSecretsMount_mssql_dual(name, name2, path, pluginName string, parsedURL *url.URL, parsedURL2 *url.URL) string {
	password, _ := parsedURL.User.Password()
	password2, _ := parsedURL2.User.Password()

	config := `
  mssql {
    allowed_roles     = ["dev1"]
    plugin_name       = "%s"
    name              = "%s"
    connection_url    = "%s"
	username          = "%s"
	password          = "%s"
    verify_connection = true
  }

  mssql {
    allowed_roles     = ["dev2"]
    plugin_name       = "%s"
    name              = "%s"
    connection_url    = "%s"
	username          = "%s"
	password          = "%s"
    verify_connection = true
  }
`
	result := fmt.Sprintf(`
resource "vault_database_secrets_mount" "db" {
  path = "%s"
%s
}

resource "vault_database_secret_backend_role" "test" {
  backend = vault_database_secrets_mount.db.path
  name    = "dev1"
  db_name = vault_database_secrets_mount.db.mssql[0].name
  creation_statements = [
    "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';",
    "CREATE USER [{{name}}] FOR LOGIN [{{name}}];",
    "GRANT SELECT ON SCHEMA::dbo TO [{{name}}];",
  ]
}

resource "vault_database_secret_backend_role" "test2" {
  backend = vault_database_secrets_mount.db.path
  name    = "dev2"
  db_name = vault_database_secrets_mount.db.mssql[1].name
  creation_statements = [
    "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';",
    "CREATE USER [{{name}}] FOR LOGIN [{{name}}];",
    "GRANT SELECT ON SCHEMA::dbo TO [{{name}}];",
  ]
}
`, path, fmt.Sprintf(config, pluginName, name, parsedURL.String(), parsedURL.User.Username(), password, pluginName,
		name2, parsedURL2.String(), parsedURL2.User.Username(), password2))

	return result
}

func testAccDatabaseSecretsMount_postgres_automatedRootRotation(name, path, connURL, schedule string, period, window int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_database_secrets_mount" "test" {
  path = "%s"

  postgresql {
    name              = "%s"
    connection_url    = "%s"
    rotation_period   = "%d"
    rotation_schedule = "%s"
    rotation_window   = "%d"
    disable_automated_rotation = %t
  }
}
`, path, name, connURL, period, schedule, window, disable)
}

func testAccDatabaseSecretsMount_hana(name, path, pluginName, connURL, username, password, userTempl string) string {
	config := `
  hana {
    allowed_roles      = ["dev", "prod"]
    plugin_name        = "%s"
    name               = "%s"
    connection_url     = "%s"
    username           = "%s"
    password           = "%s"
    disable_escaping   = true
    username_template  = "%s"
    verify_connection  = true
  }`

	result := fmt.Sprintf(`
resource "vault_database_secrets_mount" "db" {
  path = "%s"
%s
}

resource "vault_database_secret_backend_role" "test" {
  backend = vault_database_secrets_mount.db.path
  name    = "dev"
  db_name = vault_database_secrets_mount.db.hana[0].name
  creation_statements = [
    "CREATE USER {{name}} PASSWORD \"{{password}}\" VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON SCHEMA _SYS_BIC TO {{name}};",
  ]
}
`, path, fmt.Sprintf(config, pluginName, name, connURL, username, password, userTempl))

	return result
}

func TestAccDatabaseSecretsMount_mongodbatlas(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMongoDBAtlas)

	values := testutil.SkipTestEnvUnset(t,
		"MONGODB_ATLAS_PUBLIC_KEY",
		"MONGODB_ATLAS_PRIVATE_KEY",
		"MONGODB_ATLAS_PROJECT_ID")

	publicKey, privateKey, projectID := values[0], values[1], values[2]

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineMongoDBAtlas.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	name2 := name + "-2"
	usernameTemplate := "{{.DisplayName}}"

	importIgnoreKeys := []string{
		"engine_count",
		"mongodbatlas.0.verify_connection",
		"mongodbatlas.0.private_key",
	}
	resourceType := "vault_database_secrets_mount"
	resourceName := resourceType + ".db"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeDatabase, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretsMount_mongodbatlas(name, backend, pluginName, publicKey, privateKey, projectID, usernameTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.public_key", publicKey),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.private_key", privateKey),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.project_id", projectID),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.username_template", usernameTemplate),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.name", name),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importIgnoreKeys,
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					resp, err := client.Logical().Read(fmt.Sprintf("%s/creds/%s", backend, "dev"))
					if err != nil {
						t.Fatal(err)
					}
					if resp == nil {
						t.Fatal("empty response")
					}
				},
				Config: testAccDatabaseSecretsMount_mongodbatlas(name2, backend, pluginName, publicKey, privateKey, projectID, usernameTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.public_key", publicKey),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.private_key", privateKey),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.project_id", projectID),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.username_template", usernameTemplate),
					resource.TestCheckResourceAttr(resourceName, "mongodbatlas.0.name", name2),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importIgnoreKeys,
			},
		},
	})
}

func testAccDatabaseSecretsMount_mongodbatlas(name, path, pluginName, publicKey, privateKey, projectID, usernameTemplate string) string {
	config := `
  mongodbatlas {
    allowed_roles     = ["dev", "prod"]
    plugin_name       = "%s"
    name              = "%s"
    public_key        = "%s"
    private_key       = "%s"
    project_id        = "%s"
    username_template = "%s"
    verify_connection = true
  }`

	result := fmt.Sprintf(`
resource "vault_database_secrets_mount" "db" {
  path = "%s"
%s
}

resource "vault_database_secret_backend_role" "test" {
  backend = vault_database_secrets_mount.db.path
  name    = "dev"
  db_name = vault_database_secrets_mount.db.mongodbatlas[0].name
  creation_statements = [
    "{\"databaseName\": \"admin\", \"roles\": [{\"databaseName\": \"admin\", \"roleName\": \"readWrite\"}]}"
  ]
}
`, path, fmt.Sprintf(config, pluginName, name, publicKey, privateKey, projectID, usernameTemplate))

	return result
}

// TestAccDatabaseSecretsMount_cassandra tests basic Cassandra configuration
// with TLS setting from environment variable
func TestAccDatabaseSecretsMount_cassandra(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineCassandra)

	values := testutil.SkipTestEnvUnset(t, "CASSANDRA_HOST")
	host := values[0]

	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	// Get TLS setting from environment, default to false if not set
	tlsStr := os.Getenv("CASSANDRA_TLS")
	if tlsStr == "" {
		tlsStr = "false"
	}
	useTLS, err := strconv.ParseBool(tlsStr)
	if err != nil {
		t.Fatalf("Invalid CASSANDRA_TLS value: %s", tlsStr)
	}

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineCassandra.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	importIgnoreKeys := []string{
		"engine_count",
		"cassandra.0.verify_connection",
		"cassandra.0.password",
	}
	resourceType := "vault_database_secrets_mount"
	resourceName := resourceType + ".db"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeDatabase, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretsMount_cassandra(name, backend, pluginName, host, username, password, useTLS),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cassandra.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.hosts.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.hosts.0", host),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.port", "9042"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.username", username),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.name", name),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.tls", strconv.FormatBool(useTLS)),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.protocol_version", "4"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.connect_timeout", "5"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importIgnoreKeys,
			},
		},
	})
}

// TestAccDatabaseSecretsMount_cassandra_customFields tests Cassandra with all custom fields when TLS is enabled
func TestAccDatabaseSecretsMount_cassandra_customFields(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineCassandra)

	values := testutil.SkipTestEnvUnset(t, "CASSANDRA_HOST")
	host := values[0]
	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")

	// Skip if TLS is not enabled
	tlsStr := os.Getenv("CASSANDRA_TLS")
	if tlsStr == "" {
		tlsStr = "false"
	}
	useTLS, err := strconv.ParseBool(tlsStr)
	if err != nil {
		t.Fatalf("Invalid CASSANDRA_TLS value: %s", tlsStr)
	}
	if !useTLS {
		t.Skip("Skipping TLS test because CASSANDRA_TLS is not set to true")
	}

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineCassandra.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	resourceType := "vault_database_secrets_mount"
	resourceName := resourceType + ".db"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeDatabase, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretsMount_cassandra_customFields(name, backend, pluginName, host, username, password, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cassandra.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.name", name),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.tls", "true"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.tls_server_name", "cassandra-server"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.insecure_tls", "true"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.local_datacenter", "datacenter1"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.socket_keep_alive", "30"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.consistency", "LOCAL_QUORUM"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.username_template", "vault_{{.RoleName}}_{{.DisplayName}}_{{random 10}}"),
				),
			},
		},
	})
}

// TestAccDatabaseSecretsMount_cassandra_customFieldsNoTLS tests Cassandra with all custom fields when TLS is disabled
func TestAccDatabaseSecretsMount_cassandra_customFieldsNoTLS(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineCassandra)

	values := testutil.SkipTestEnvUnset(t, "CASSANDRA_HOST")
	host := values[0]
	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")

	// Skip if TLS is enabled
	tlsStr := os.Getenv("CASSANDRA_TLS")
	if tlsStr == "" {
		tlsStr = "false"
	}
	useTLS, err := strconv.ParseBool(tlsStr)
	if err != nil {
		t.Fatalf("Invalid CASSANDRA_TLS value: %s", tlsStr)
	}
	if useTLS {
		t.Skip("Skipping non-TLS test because CASSANDRA_TLS is set to true")
	}

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineCassandra.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	resourceType := "vault_database_secrets_mount"
	resourceName := resourceType + ".db"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeDatabase, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretsMount_cassandra_customFields(name, backend, pluginName, host, username, password, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cassandra.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.name", name),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.tls", "false"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.local_datacenter", "datacenter1"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.socket_keep_alive", "30"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.consistency", "LOCAL_QUORUM"),
					resource.TestCheckResourceAttr(resourceName, "cassandra.0.username_template", "vault_{{.RoleName}}_{{.DisplayName}}_{{random 10}}"),
				),
			},
		},
	})
}

func testAccDatabaseSecretsMount_cassandra(name, path, pluginName, host, username, password string, useTLS bool) string {
	tlsFields := ""
	if useTLS {
		tlsFields = `
    insecure_tls      = true`
	}

	config := fmt.Sprintf(`
  cassandra {
    allowed_roles     = ["dev", "prod"]
    plugin_name       = "%s"
    name              = "%s"
    hosts             = ["%s"]
    port              = 9042
    username          = "%s"
    password          = "%s"
    tls               = %t%s
    protocol_version  = 4
    connect_timeout   = 5
    verify_connection = true
  }`, pluginName, name, host, username, password, useTLS, tlsFields)

	result := fmt.Sprintf(`
resource "vault_database_secrets_mount" "db" {
  path = "%s"
%s
}

resource "vault_database_secret_backend_role" "test" {
  backend = vault_database_secrets_mount.db.path
  name    = "dev"
  db_name = vault_database_secrets_mount.db.cassandra[0].name
  creation_statements = [
    "CREATE USER '{{name}}' WITH PASSWORD '{{password}}' NOSUPERUSER;",
    "GRANT SELECT ON ALL KEYSPACES TO '{{name}}';",
  ]
}
`, path, config)

	return result
}

func testAccDatabaseSecretsMount_cassandra_customFields(name, path, pluginName, host, username, password string, useTLS bool) string {
	tlsFields := ""
	if useTLS {
		tlsFields = `
    tls_server_name     = "cassandra-server"
    insecure_tls        = true`
	}

	config := fmt.Sprintf(`
  cassandra {
    allowed_roles       = ["dev", "prod"]
    plugin_name         = "%s"
    name                = "%s"
    hosts               = ["%s"]
    port                = 9042
    username            = "%s"
    password            = "%s"
    tls                 = %t%s
    local_datacenter    = "datacenter1"
    socket_keep_alive   = 30
    consistency         = "LOCAL_QUORUM"
    username_template   = "vault_{{.RoleName}}_{{.DisplayName}}_{{random 10}}"
    protocol_version    = 4
    connect_timeout     = 30
    verify_connection   = true
  }`, pluginName, name, host, username, password, useTLS, tlsFields)

	result := fmt.Sprintf(`
resource "vault_database_secrets_mount" "db" {
  path = "%s"
%s
}

resource "vault_database_secret_backend_role" "test" {
  backend = vault_database_secrets_mount.db.path
  name    = "dev"
  db_name = vault_database_secrets_mount.db.cassandra[0].name
  creation_statements = [
    "CREATE USER '{{name}}' WITH PASSWORD '{{password}}' NOSUPERUSER;",
    "GRANT SELECT ON ALL KEYSPACES TO '{{name}}';",
  ]
}
`, path, config)

	return result
}
