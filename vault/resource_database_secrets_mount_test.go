// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	mssqlhelper "github.com/hashicorp/vault/helper/testhelpers/mssql"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDatabaseSecretsMount_mssql(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMSSQL)

	cleanupFunc, connURL := mssqlhelper.PrepareMSSQLTestContainer(t)

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
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeDatabase, consts.FieldPath),
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
					client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

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

	cleanupFunc, connURL := mssqlhelper.PrepareMSSQLTestContainer(t)
	t.Cleanup(cleanupFunc)

	cleanupFunc2, connURL2 := mssqlhelper.PrepareMSSQLTestContainer(t)
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
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeDatabase, consts.FieldPath),
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
					client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

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
