package vault

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccDatabaseSecretBackendConnection_import(t *testing.T) {
	connURL := os.Getenv("POSTGRES_URL")
	if connURL == "" {
		t.Skip("POSTGRES_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_connection_lifetime", "0"),
				),
			},
			{
				ResourceName:            "vault_database_secret_backend_connection.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "postgresql.0.connection_url"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_cassandra(t *testing.T) {
	host := os.Getenv("CASSANDRA_HOST")
	if host == "" {
		t.Skip("CASSANDRA_HOST not set")
	}

	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_cassandra(name, backend, host, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.hosts.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.hosts.0", host),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.port", "9042"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.username", username),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.password", password),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.tls", "false"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.insecure_tls", "false"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.pem_bundle", ""),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.pem_json", ""),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.protocol_version", "4"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.connect_timeout", "5"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_cassandraProtocol(t *testing.T) {
	host := os.Getenv("CASSANDRA_HOST")
	if host == "" {
		t.Skip("CASSANDRA_HOST not set")
	}

	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_cassandraProtocol(name, backend, host, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.hosts.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.hosts.0", host),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.port", "9042"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.username", username),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.password", password),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.tls", "false"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.insecure_tls", "false"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.pem_bundle", ""),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.pem_json", ""),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.protocol_version", "5"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.connect_timeout", "5"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mongodb(t *testing.T) {
	connURL := os.Getenv("MONGODB_URL")
	if connURL == "" {
		t.Skip("MONGODB_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mongodb(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mongodb.0.connection_url", connURL),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mssql(t *testing.T) {
	connURL := os.Getenv("MSSQL_URL")
	if connURL == "" {
		t.Skip("MSSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mssql(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.max_connection_lifetime", "0"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	password := acctest.RandomWithPrefix("password")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql(name, backend, connURL, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", password),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_rds(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_rds.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_rds.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_rds.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_rds.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_aurora(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_aurora.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_aurora.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_aurora.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_aurora.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_legacy(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_legacy.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_legacy.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_legacy.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_legacy.0.max_connection_lifetime", "0"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnectionUpdate_mysql(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	password := acctest.RandomWithPrefix("password")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, backend, connURL, password, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", password),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, backend, connURL, password, 10),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "10"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", password),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_postgresql(t *testing.T) {
	connURL := os.Getenv("POSTGRES_URL")
	if connURL == "" {
		t.Skip("POSTGRES_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_connection_lifetime", "0"),
				),
			},
		},
	})
}

func testAccDatabaseSecretBackendConnectionCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_database_secret_backend_connection" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("connection %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccDatabaseSecretBackendConnectionConfig_cassandra(name, path, host, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  cassandra {
    hosts = ["%s"]
    username = "%s"
    password = "%s"
    tls = false
  }
}
`, path, name, host, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_cassandraProtocol(name, path, host, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  cassandra {
    hosts = ["%s"]
    username = "%s"
    password = "%s"
    tls = false
    protocol_version = 5
  }
}
`, path, name, host, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mongodb(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mongodb {
    connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_mssql(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mssql {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql(name, path, connURL, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql {
	  connection_url = "%s"
  }

  data = {
	  password = "%s"
  }
}
`, path, name, connURL, password)
}

func testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, path, connURL, password string, connLifetime int) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql {
	  connection_url = "%s"
	  max_connection_lifetime = "%d"
  }

  data = {
	  password = "%s"
  }
}
`, path, name, connURL, connLifetime, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_rds(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql_rds {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_aurora(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql_aurora {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_legacy(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql_legacy {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_postgresql(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  postgresql {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}
