package vault

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	mssqlhelper "github.com/hashicorp/vault/helper/testhelpers/mssql"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TODO: add support for automating tests for plugin_name
// Currently we have to configure the Vault server with a plugin_directory,
// copy/build a db plugin and install it with a unique name, then register it in vault.

func TestAccDatabaseSecretBackendConnection_import(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendPostgres)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	userTempl := "{{.DisplayName}}"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql(name, backend, connURL, userTempl),
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.username_template", userTempl),
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
	MaybeSkipDBTests(t, dbBackendCassandra)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "CASSANDRA_HOST")
	host := values[0]

	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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
	MaybeSkipDBTests(t, dbBackendCassandra)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "CASSANDRA_HOST")
	host := values[0]

	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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

func TestAccDatabaseSecretBackendConnection_couchbase(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendCouchbase)

	values := testutil.SkipTestEnvUnset(t, "COUCHBASE_HOST_1", "COUCHBASE_HOST_2", "COUCHBASE_USERNAME", "COUCHBASE_PASSWORD")
	host1 := values[0]
	host2 := values[1]
	username := values[2]
	password := values[3]
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resourceName := "vault_database_secret_backend_connection.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_couchbase(name, backend, host1, host2, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(resourceName, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(resourceName, "verify_connection", "true"),
					resource.TestCheckResourceAttr(resourceName, "couchbase.0.hosts.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "couchbase.0.hosts.*", host1),
					resource.TestCheckTypeSetElemAttr(resourceName, "couchbase.0.hosts.*", host2),
					resource.TestCheckResourceAttr(resourceName, "couchbase.0.username", username),
					resource.TestCheckResourceAttr(resourceName, "couchbase.0.password", password),
					resource.TestCheckResourceAttr(resourceName, "couchbase.0.tls", "false"),
					resource.TestCheckResourceAttr(resourceName, "couchbase.0.insecure_tls", "false"),
					resource.TestCheckResourceAttr(resourceName, "couchbase.0.base64_pem", ""),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "couchbase.0.password"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_influxdb(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendInfluxDB)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "INFLUXDB_HOST")
	host := values[0]

	username := os.Getenv("INFLUXDB_USERNAME")
	password := os.Getenv("INFLUXDB_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resourceName := "vault_database_secret_backend_connection.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_influxdb(name, backend, host, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(resourceName, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(resourceName, "verify_connection", "true"),
					resource.TestCheckResourceAttr(resourceName, "influxdb.0.host", host),
					resource.TestCheckResourceAttr(resourceName, "influxdb.0.port", "8086"),
					resource.TestCheckResourceAttr(resourceName, "influxdb.0.username", username),
					resource.TestCheckResourceAttr(resourceName, "influxdb.0.password", password),
					resource.TestCheckResourceAttr(resourceName, "influxdb.0.tls", "false"),
					resource.TestCheckResourceAttr(resourceName, "influxdb.0.insecure_tls", "false"),
					resource.TestCheckResourceAttr(resourceName, "influxdb.0.pem_bundle", ""),
					resource.TestCheckResourceAttr(resourceName, "influxdb.0.pem_json", ""),
					resource.TestCheckResourceAttr(resourceName, "influxdb.0.connect_timeout", "5"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mongodbatlas(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendMongoDBAtlas)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "MONGODB_ATLAS_PUBLIC_KEY")
	publicKey := values[0]

	privateKey := os.Getenv("MONGODB_ATLAS_PRIVATE_KEY")
	projectID := os.Getenv("MONGODB_ATLAS_PROJECT_ID")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mongodbatlas(name, backend, publicKey, privateKey, projectID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mongodbatlas.0.public_key", publicKey),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mongodbatlas.0.private_key", privateKey),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mongodbatlas.0.project_id", projectID),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mongodb(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendMongoDB)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "MONGODB_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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
	MaybeSkipDBTests(t, dbBackendMSSQL)

	cleanupFunc, connURL := mssqlhelper.PrepareMSSQLTestContainer(t)

	t.Cleanup(cleanupFunc)

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	// should match dbEngine.getPluginName()'s default return value
	pluginName := fmt.Sprintf("%s-database-plugin", dbBackendMSSQL)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mssql(name, backend, connURL, pluginName, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "plugin_name", pluginName),
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.contained_db", "false"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mssql(name, backend, connURL, pluginName, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "plugin_name", pluginName),
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.contained_db", "true"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "MYSQL_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	password := acctest.RandomWithPrefix("password")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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
	MaybeSkipDBTests(t, dbBackendMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "MYSQL_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	password := acctest.RandomWithPrefix("password")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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

func TestAccDatabaseSecretBackendConnectionTemplatedUpdateExcludePassword_mysql(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t,
		"MYSQL_CONNECTION_URL",
		"MYSQL_CONNECTION_USERNAME",
		"MYSQL_CONNECTION_PASSWORD")

	connURL, username, password := values[0], values[1], values[2]

	// The MYQSL_CONNECTION_* vars are from within the test suite (might be different host due to docker)
	// They are used to create test DB users
	// MYSQL_TEMPLATED_URL is the template URL to be used in vault
	testConnURL := os.Getenv("MYSQL_TEMPLATED_URL")
	if testConnURL == "" {
		testConnURL = connURL
	}

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	testUsername := acctest.RandomWithPrefix("username")
	testPassword := acctest.RandomWithPrefix("password")

	db := newMySQLConnection(t, connURL, username, password)
	createMySQSUser(t, db, testUsername, testPassword)
	defer deleteMySQLUser(t, db, testUsername)

	client := testProvider.Meta().(*api.Client)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfigTemplated_mysql(name, backend, testConnURL, testUsername, testPassword, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", testConnURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.username", testUsername),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", testPassword),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfigTemplated_mysql(name, backend, testConnURL, testUsername, testPassword, 10),
				PreConfig: func() {
					path := fmt.Sprintf("%s/rotate-root/%s", backend, name)
					resp, err := client.Logical().Write(path, map[string]interface{}{})
					if err != nil {
						t.Error(err)
					}

					log.Printf("rotate-root: %v", resp)
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", testConnURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "10"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.username", testUsername),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", testPassword),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql_tls(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "MYSQL_CA", "MYSQL_URL", "MYSQL_CERTIFICATE_KEY")
	tlsCA, connURL, tlsCertificateKey := values[0], values[1], values[2]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	password := acctest.RandomWithPrefix("password")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_tls(name, backend, connURL, password, tlsCA, tlsCertificateKey),
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.tlsCA", tlsCA+"\n"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.tls_certificate_key", tlsCertificateKey+"\n"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_postgresql(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendPostgres)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	userTempl := "{{.DisplayName}}"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql(name, backend, connURL, userTempl),
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
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.username_template", userTempl),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_elasticsearch(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendElasticSearch)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "ELASTIC_URL")
	connURL := values[0]

	username := os.Getenv("ELASTIC_USERNAME")
	password := os.Getenv("ELASTIC_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_elasticsearch(name, backend, connURL, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "elasticsearch.0.url", connURL),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_snowflake(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendSnowflake)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "SNOWFLAKE_URL")
	connURL := values[0]

	username := os.Getenv("SNOWFLAKE_USERNAME")
	password := os.Getenv("SNOWFLAKE_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	userTempl := "{{.DisplayName}}"

	config := testAccDatabaseSecretBackendConnectionConfig_snowflake(name, backend, connURL, username, password, userTempl)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.username", username),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.password", password),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.username_template", userTempl),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_redshift(t *testing.T) {
	MaybeSkipDBTests(t, dbBackendRedshift)

	url := os.Getenv("REDSHIFT_URL")
	if url == "" {
		t.Skip("REDSHIFT_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redshift(name, backend, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "redshift.0.connection_url", url),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "redshift.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "redshift.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "redshift.0.max_connection_lifetime", "0"),
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
  backend = vault_mount.db.path
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
  backend = vault_mount.db.path
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

func testAccDatabaseSecretBackendConnectionConfig_influxdb(name, path, host, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend                  = vault_mount.db.path
  name                     = "%s"
  allowed_roles            = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  influxdb {
    host     = "%s"
    username = "%s"
    password = "%s"
    tls      = false
  }
}
`, path, name, host, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_couchbase(name, path, host1, host2, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}
resource "vault_database_secret_backend_connection" "test" {
  backend                  = vault_mount.db.path
  name                     = "%s"
  allowed_roles            = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]
  couchbase {
    hosts    = ["%s", "%s"]
    username = "%s"
    password = "%s"
  }
}
`, path, name, host1, host2, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_elasticsearch(name, path, host, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  elasticsearch {
    url = "%s"
    username = "%s"
    password = "%s"
  }
}
`, path, name, host, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mongodbatlas(name, path, public_key, private_key, project_id string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mongodbatlas {
    public_key  = "%s"
    private_key = "%s"
    project_id  = "%s"
  }
}
`, path, name, public_key, private_key, project_id)
}

func testAccDatabaseSecretBackendConnectionConfig_mongodb(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mongodb {
    connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_mssql(name, path, connURL, pluginName string, containedDB bool) string {
	var config string
	if containedDB {
		config = `
  mssql {
    connection_url = "%s"
    contained_db   = true
  }`
	} else {
		config = `
  mssql {
    connection_url = "%s"
  }`
	}

	result := fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  plugin_name = "%s"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]
%s
}
`, path, pluginName, name, fmt.Sprintf(config, connURL))

	return result
}

func testAccDatabaseSecretBackendConnectionConfig_mysql(name, path, connURL, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
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
  backend = vault_mount.db.path
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

func testAccDatabaseSecretBackendConnectionConfig_mysql_tls(name, path, connURL, password, tls_ca, tls_certificate_key string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql {
	  connection_url = "%s"
	  tls_ca              = <<EOT
%s
EOT
	  tls_certificate_key = <<EOT
%s
EOT
  }

  data = {
	  password            = "%s"
  }
}
`, path, name, connURL, tls_ca, tls_certificate_key, password)
}

func testAccDatabaseSecretBackendConnectionConfigTemplated_mysql(name, path, connURL, username, password string, connLifetime int) string {
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
	  connection_url          = "%s"
	  max_connection_lifetime = "%d"
  }

  data = {
	  username = "%s"
	  password = "%s"
  }
}
`, path, name, connURL, connLifetime, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_rds(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
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
  backend = vault_mount.db.path
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
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql_legacy {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_postgresql(name, path, connURL, userTempl string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  postgresql {
	  connection_url = "%s"
	  username_template = "%s"
  }
}
`, path, name, connURL, userTempl)
}

func testAccDatabaseSecretBackendConnectionConfig_snowflake(name, path, url, username, password, userTempl string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  snowflake { 
    connection_url = "%s"
    username = "%s"
    password = "%s"
    username_template = "%s"
  }
}
`, path, name, url, username, password, userTempl)
}

func testAccDatabaseSecretBackendConnectionConfig_redshift(name, path, connURL string) string {
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
  redshift {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func newMySQLConnection(t *testing.T, connURL string, username string, password string) *sql.DB {
	dbURL := dbutil.QueryHelper(connURL, map[string]string{
		"username": username,
		"password": password,
	})

	db, err := sql.Open("mysql", dbURL)
	if err != nil {
		t.Fatal(err)
	}

	return db
}

func createMySQSUser(t *testing.T, db *sql.DB, username string, password string) {
	createUser := fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s';", username, password)
	grantPrivileges := fmt.Sprintf("GRANT ALL PRIVILEGES ON *.* TO '%s'@'%%' WITH GRANT OPTION;", username)

	_, err := db.Exec(createUser)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(grantPrivileges)
	if err != nil {
		t.Fatal(err)
	}
}

func deleteMySQLUser(t *testing.T, db *sql.DB, username string) {
	query := fmt.Sprintf("DROP USER '%s'@'%%';", username)
	_, err := db.Exec(query)
	if err != nil {
		t.Error(err)
	}
}

func MaybeSkipDBTests(t *testing.T, engine string) {
	// require TF_ACC to be set
	testutil.SkipTestAcc(t)

	envVars := []string{"SKIP_DB_TESTS"}
	for _, e := range dbBackendTypes {
		if e == engine {
			envVars = append(envVars, envVars[0]+"_"+strings.ToUpper(engine))
			break
		}
	}
	testutil.SkipTestEnvSet(t, envVars...)
}

func Test_dbEngine_getPluginName(t *testing.T) {
	type fields struct {
		name string
	}
	type args struct {
		d *schema.ResourceData
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "default",
			fields: fields{
				name: "foo",
			},
			args: args{
				schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"plugin_name": {
							Type:     schema.TypeString,
							Required: false,
						},
					},
					map[string]interface{}{}),
			},
			want: "foo-database-plugin",
		},
		{
			name: "default-underscored",
			fields: fields{
				name: "foo_qux_baz",
			},
			args: args{
				schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"plugin_name": {
							Type:     schema.TypeString,
							Required: false,
						},
					},
					map[string]interface{}{}),
			},
			want: "foo-qux-baz-database-plugin",
		},
		{
			name: "set",
			fields: fields{
				name: "foo",
			},
			args: args{
				schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"plugin_name": {
							Type:     schema.TypeString,
							Required: false,
						},
					},
					map[string]interface{}{
						"plugin_name": "baz-qux",
					}),
			},
			want: "baz-qux",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &dbEngine{
				name: tt.fields.name,
			}
			if got := i.getPluginName(tt.args.d); got != tt.want {
				t.Errorf("getPluginName() expected %v, actual %v", tt.want, got)
			}
		})
	}
}

func Test_getDBEngine(t *testing.T) {
	type args struct {
		d *schema.ResourceData
	}
	tests := []struct {
		name        string
		args        args
		want        *dbEngine
		wantErr     bool
		expectedErr error
	}{
		{
			name: "basic",
			args: args{
				schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"mssql": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Connection parameters for the mssql-database-plugin plugin.",
							Elem:        mssqlConnectionStringResource(),
							MaxItems:    1,
						},
					},
					map[string]interface{}{
						"mssql": []interface{}{
							map[string]interface{}{
								"connection_url": "foo",
							},
						},
					}),
			},
			want: &dbEngine{
				name: dbBackendMSSQL,
			},
			wantErr: false,
		},
		{
			name: "not-found",
			args: args{
				schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"unknown": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Connection parameters for the mssql-database-plugin plugin.",
							Elem:        mssqlConnectionStringResource(),
							MaxItems:    1,
						},
					},
					map[string]interface{}{
						"mssql": []interface{}{
							map[string]interface{}{
								"connection_url": "foo",
							},
						},
					}),
			},
			wantErr:     true,
			expectedErr: errors.New("no supported database engines configured"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getDBEngine(tt.args.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDBEngine() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && tt.expectedErr != nil {
				if !reflect.DeepEqual(err, tt.expectedErr) {
					t.Fatalf("getDBEngine() expected err %v, actual %v", tt.expectedErr, err)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getDBEngine() expected %v, actual %v", tt.want, got)
			}
		})
	}
}
