// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const testDefaultDatabaseSecretBackendResource = "vault_database_secret_backend_connection.test"

// TODO: add support for automating tests for plugin_name
// Currently we have to configure the Vault server with a plugin_directory,
// copy/build a db plugin and install it with a unique name, then register it in vault.

func TestAccDatabaseSecretBackendConnection_postgresql_import(t *testing.T) {
	MaybeSkipDBTests(t, dbEnginePostgres)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEnginePostgres.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	userTempl := "{{.DisplayName}}"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_import(name, backend, connURL, userTempl),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.username_template", userTempl),
				),
			},
			{
				ResourceName:            testDefaultDatabaseSecretBackendResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "postgresql.0.connection_url"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_cassandra(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineCassandra)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "CASSANDRA_HOST")
	host := values[0]

	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineCassandra.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_cassandra(name, backend, host, username, password, "5"),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.hosts.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.hosts.0", host),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.port", "9042"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.tls", "false"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.insecure_tls", "false"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.pem_bundle", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.pem_json", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.protocol_version", "4"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.connect_timeout", "5"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.skip_verification", "false"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_cassandraProtocol(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineCassandra)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "CASSANDRA_HOST")
	host := values[0]

	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineCassandra.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_cassandraProtocol(name, backend, host, username, password),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.hosts.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.hosts.0", host),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.port", "9042"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.tls", "false"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.insecure_tls", "false"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.pem_bundle", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.pem_json", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.protocol_version", "5"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.connect_timeout", "5"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_couchbase(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineCouchbase)

	values := testutil.SkipTestEnvUnset(t, "COUCHBASE_HOST", "COUCHBASE_USERNAME", "COUCHBASE_PASSWORD")
	host := values[0]
	username := values[1]
	password := values[2]

	localCouchbaseHost := host
	runsInContainer := os.Getenv("RUNS_IN_CONTAINER") == "true"
	if !runsInContainer {
		localCouchbaseHost = "localhost"
	}

	hostTLS := fmt.Sprintf("couchbases://%s", host)

	getBase64PEM := func(host string) string {
		resp, err := http.Get(fmt.Sprintf("http://%s:8091/pools/default/certificate", host))
		if err != nil {
			t.Fatal(err)
		}

		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(b)
	}

	host1Base64PEM := getBase64PEM(localCouchbaseHost)

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineCouchbase.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	resourceName := testDefaultDatabaseSecretBackendResource

	commonChecks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "allowed_roles.#", "2"),
		resource.TestCheckResourceAttr(resourceName, "allowed_roles.0", "dev"),
		resource.TestCheckResourceAttr(resourceName, "allowed_roles.1", "prod"),
		resource.TestCheckResourceAttr(resourceName, "root_rotation_statements.#", "1"),
		resource.TestCheckResourceAttr(resourceName, "root_rotation_statements.0", "FOOBAR"),
		resource.TestCheckResourceAttr(resourceName, "verify_connection", "true"),
		resource.TestCheckResourceAttr(resourceName, "couchbase.0.bucket_name", "travel-sample"),
		resource.TestCheckResourceAttr(resourceName, "couchbase.0.username", username),
		resource.TestCheckResourceAttr(resourceName, "couchbase.0.password", password),
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_couchbase(
					name, backend, host, username, password, ""),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					append(commonChecks,
						resource.TestCheckResourceAttr(resourceName, "couchbase.0.hosts.#", "1"),
						resource.TestCheckTypeSetElemAttr(resourceName, "couchbase.0.hosts.*", host),
						resource.TestCheckResourceAttr(resourceName, "couchbase.0.tls", "false"),
						resource.TestCheckResourceAttr(resourceName, "couchbase.0.insecure_tls", "false"),
						resource.TestCheckResourceAttr(resourceName, "couchbase.0.base64_pem", ""),
					)...,
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "couchbase.0.password"},
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_couchbase(
					name, backend, hostTLS, username, password, host1Base64PEM),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					append(commonChecks,
						resource.TestCheckResourceAttr(resourceName, "couchbase.0.hosts.#", "1"),
						resource.TestCheckTypeSetElemAttr(resourceName, "couchbase.0.hosts.*", hostTLS),
						resource.TestCheckResourceAttr(resourceName, "couchbase.0.tls", "true"),
						resource.TestCheckResourceAttr(resourceName, "couchbase.0.insecure_tls", "true"),
						resource.TestCheckResourceAttr(resourceName, "couchbase.0.base64_pem", host1Base64PEM),
					)...,
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
	MaybeSkipDBTests(t, dbEngineInfluxDB)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "INFLUXDB_HOST")
	host := values[0]

	username := os.Getenv("INFLUXDB_USERNAME")
	password := os.Getenv("INFLUXDB_PASSWORD")
	port := os.Getenv("INFLUXDB_PORT")
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineInfluxDB.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	resourceName := testDefaultDatabaseSecretBackendResource
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_influxdb(name, backend, host, port, username, password),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
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
	MaybeSkipDBTests(t, dbEngineMongoDBAtlas)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t,
		"MONGODB_ATLAS_PUBLIC_KEY",
		"MONGODB_ATLAS_PRIVATE_KEY",
		"MONGODB_ATLAS_PROJECT_ID")

	publicKey, privateKey, projectID := values[0], values[1], values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineMongoDBAtlas.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mongodbatlas(name, backend, publicKey, privateKey, projectID),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodbatlas.0.public_key", publicKey),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodbatlas.0.private_key", privateKey),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodbatlas.0.project_id", projectID),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mongodb(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMongoDB)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "MONGODB_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineMongoDB.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mongodb(name, backend, connURL),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodb.0.connection_url", connURL),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mssql(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMSSQL)

	cleanupFunc, connURL := testutil.PrepareMSSQLTestContainer(t)
	t.Cleanup(cleanupFunc)

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineMSSQL.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	parsedURL, err := url.Parse(connURL)
	if err != nil {
		t.Fatal(err)
	}

	username := parsedURL.User.Username()
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mssql(name, backend, pluginName, parsedURL, false),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.disable_escaping", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.contained_db", "false"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mssql(name, backend, pluginName, parsedURL, true),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "plugin_name", pluginName),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.disable_escaping", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mssql.0.contained_db", "true"),
				),
			},
			{
				ResourceName:            testDefaultDatabaseSecretBackendResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "mssql.0.password", "mssql.0.connection_url"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql_cloud(t *testing.T) {
	// wanted this to be the included with the following test, but the env-var check is different
	values := testutil.SkipTestEnvUnset(t, "MYSQL_CLOUD_CONNECTION_URL", "MYSQL_CLOUD_CONNECTION_SERVICE_ACCOUNT_JSON")
	connURL, saJSON := values[0], values[1]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_cloud(name, backend, connURL, "gcp_iam", saJSON),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, dbEngineMySQL.DefaultPluginName(),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.auth_type", "gcp_iam"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_connection_lifetime", "0"),
				),
			},
			{
				ResourceName:            testDefaultDatabaseSecretBackendResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "mysql.0.service_account_json"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t,
		"MYSQL_CONNECTION_URL", "MYSQL_CONNECTION_USERNAME", "MYSQL_CONNECTION_PASSWORD")
	connURL, username, password := values[0], values[1], values[2]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql(name, backend, connURL, username, password),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, dbEngineMySQL.DefaultPluginName(),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_rds(name, backend, connURL, username, password),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, dbEngineMySQLRDS.DefaultPluginName(),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_rds.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_rds.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_rds.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_rds.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_rds.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_aurora(name, backend, connURL, username, password),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, dbEngineMySQLAurora.DefaultPluginName(),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_legacy(name, backend, connURL, username, password),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, dbEngineMySQLLegacy.DefaultPluginName(),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_legacy.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_legacy.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_legacy.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_legacy.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_legacy.0.max_connection_lifetime", "0"),
				),
			},
		},
	})
}

func testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName string, fs ...resource.TestCheckFunc) resource.TestCheckFunc {
	funcs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "name", name),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "backend", backend),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "plugin_name", pluginName),
	}
	funcs = append(funcs, fs...)

	return resource.ComposeAggregateTestCheckFunc(funcs...)
}

func TestAccDatabaseSecretBackendConnectionUpdate_mysql(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t,
		"MYSQL_CONNECTION_URL", "MYSQL_CONNECTION_USERNAME", "MYSQL_CONNECTION_PASSWORD")
	connURL, username, password := values[0], values[1], values[2]

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineMySQL.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, backend, connURL, username, password, 0),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, backend, connURL, username, password, 10),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_connection_lifetime", "10"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnectionTemplatedUpdateExcludePassword_mysql(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMySQL)

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
	pluginName := dbEngineMySQL.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	// setup a secondary root user which is required for the rotate-root test portion below.
	secondaryRootUsername := acctest.RandomWithPrefix("username")
	secondaryRootPassword := acctest.RandomWithPrefix("password")
	db := newMySQLConnection(t, connURL, username, password)
	createMySQLUser(t, db, secondaryRootUsername, secondaryRootPassword)
	t.Cleanup(func() {
		deleteMySQLUser(t, db, secondaryRootUsername)
	})

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfigTemplated_mysql(name, backend, testConnURL, username, password, 0),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.connection_url", testConnURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfigTemplated_mysql(name, backend, testConnURL, secondaryRootUsername, secondaryRootPassword, 10),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.connection_url", testConnURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.username", secondaryRootUsername),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.password", secondaryRootPassword),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_connection_lifetime", "10"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfigTemplated_mysql(name, backend, testConnURL, secondaryRootUsername, secondaryRootPassword, 15),
				PreConfig: func() {
					path := fmt.Sprintf("%s/rotate-root/%s", backend, name)
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					resp, err := client.Logical().Write(path, map[string]interface{}{})
					if err != nil {
						t.Error(err)
					}

					log.Printf("rotate-root: %v", resp)
				},
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.connection_url", testConnURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_connection_lifetime", "15"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.username", secondaryRootUsername),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.password", secondaryRootPassword),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql_tls(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "MYSQL_CA", "MYSQL_URL", "MYSQL_CERTIFICATE_KEY")
	tlsCA, connURL, tlsCertificateKey := values[0], values[1], values[2]

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineMySQL.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	password := acctest.RandomWithPrefix("password")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_tls(name, backend, connURL, password, tlsCA, tlsCertificateKey),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "data.%", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "data.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.tls_ca", tlsCA+"\n"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.tls_certificate_key", tlsCertificateKey+"\n"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_aurora_tls(name, backend, connURL, password, tlsCA, tlsCertificateKey),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "data.%", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "data.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.tls_ca", tlsCA+"\n"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql_aurora.0.tls_certificate_key", tlsCertificateKey+"\n"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_postgresql(t *testing.T) {
	MaybeSkipDBTests(t, dbEnginePostgres)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	connURL := values[0]
	parsedURL, err := url.Parse(connURL)
	if err != nil {
		t.Fatal(err)
	}

	username := parsedURL.User.Username()
	password, _ := parsedURL.User.Password()
	maxOpenConnections := "16"
	maxIdleConnections := "8"
	maxConnLifetime := "200"
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEnginePostgres.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	userTempl := "{{.DisplayName}}"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql(name, backend, userTempl, username, password, maxOpenConnections, maxIdleConnections, maxConnLifetime, parsedURL),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_open_connections", maxOpenConnections),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_idle_connections", maxIdleConnections),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_connection_lifetime", maxConnLifetime),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.disable_escaping", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.username_template", userTempl),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql_reset_optional_values(name, backend, parsedURL),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.username", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.password", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.disable_escaping", "false"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.username_template", ""),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_postgresql_tls(t *testing.T) {
	resourceName := "vault_database_secret_backend_connection.test"
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEnginePostgres.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql_tls(name, backend, testPostgresCACert, testPostgresClientCert, testPostgresClientKey),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(resourceName, "postgresql.0.tls_ca", testPostgresCACert),
					resource.TestCheckResourceAttr(resourceName, "postgresql.0.tls_certificate", testPostgresClientCert),
					resource.TestCheckResourceAttr(resourceName, "postgresql.0.private_key", testPostgresClientKey),
				),
			},
			// the private key is a secret that is never revealed by Vault
			testutil.GetImportTestStep(resourceName, false, nil, "postgresql.0.private_key"),
		},
	})
}

func TestAccDatabaseSecretBackendConnection_postgresql_cloud(t *testing.T) {
	// wanted this to be the included with the following test, but the env-var check is different
	values := testutil.SkipTestEnvUnset(t, "POSTGRES_CLOUD_URL", "POSTGRES_CLOUD_SERVICE_ACCOUNT_JSON")
	connURL, saJSON := values[0], values[1]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgres_cloud(name, backend, connURL, "gcp_iam", saJSON),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, dbEngineMySQL.DefaultPluginName(),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.disable_escaping", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.auth_type", "gcp_iam"),
				),
			},
			{
				ResourceName:            testDefaultDatabaseSecretBackendResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "postgres.0.service_account_json"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_elasticsearch(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineElasticSearch)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "ELASTIC_URL")
	connURL := values[0]

	username := os.Getenv("ELASTIC_USERNAME")
	password := os.Getenv("ELASTIC_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineElasticSearch.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_elasticsearch(name, backend, connURL, username, password),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.insecure", "false"),
				),
			},
			{
				ResourceName:            testDefaultDatabaseSecretBackendResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "elasticsearch.0.password"},
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_elasticsearchUpdated(name, backend, connURL, username, password, "test"),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.insecure", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.username_template", "test"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.tls_server_name", "test"),
				),
			},
			{
				PreConfig: func() {
					// Uncomment block below to actually rotate root. We're avoiding doing this in CI test runs
					// because it will change the password and cause (future) tests to 401.

					//path := fmt.Sprintf("%s/rotate-root/%s", backend, name)
					//client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
					//
					//_, err := client.Logical().Write(path, map[string]interface{}{})
					//if err != nil {
					//	t.Error(err)
					//}
				},
				// assert that after rotating root, the password stored in state does not change.
				Config: testAccDatabaseSecretBackendConnectionConfig_elasticsearchUpdated(name, backend, connURL, username, password, "foobar"),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "elasticsearch.0.username_template", "foobar"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_snowflake(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineSnowflake)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "SNOWFLAKE_URL")
	connURL := values[0]

	username := os.Getenv("SNOWFLAKE_USERNAME")
	password := os.Getenv("SNOWFLAKE_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineSnowflake.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	userTempl := "{{.DisplayName}}"

	config := testAccDatabaseSecretBackendConnectionConfig_snowflake(name, backend, connURL, username, password, userTempl)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.username_template", userTempl),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_redis(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineRedis)

	values := testutil.SkipTestEnvUnset(t, "REDIS_HOST", "REDIS_PORT", "REDIS_USERNAME", "REDIS_PASSWORD")
	host := values[0]
	port := values[1]
	username := values[2]
	password := values[3]

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineRedis.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redis(name, backend, host, port, username, password, "*"),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "*"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.host", host),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.port", "6379"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.tls", "false"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.insecure_tls", "false"),
				),
			},
			{
				PreConfig: func() {
					// Uncomment block below to actually rotate root. We're avoiding doing this in CI test runs
					// because it will change the password and cause (future) tests to 401.

					//path := fmt.Sprintf("%s/rotate-root/%s", backend, name)
					//client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
					//
					//_, err := client.Logical().Write(path, map[string]interface{}{})
					//if err != nil {
					//	t.Error(err)
					//}
				},
				Config: testAccDatabaseSecretBackendConnectionConfig_redis(name, backend, host, port, username, password, "foobar"),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "foobar"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.password", password),
				),
			},
			{
				ResourceName:            testDefaultDatabaseSecretBackendResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "redis.0.password"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_redisElastiCache(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineRedisElastiCache)

	url := os.Getenv("ELASTICACHE_URL")
	if url == "" {
		t.Skip("ELASTICACHE_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineRedisElastiCache.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redis_elasticache(name, backend, url),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "*"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis_elasticache.0.url", url),
				),
			},
			{
				ResourceName:            testDefaultDatabaseSecretBackendResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "redis_elasticache.0.password"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_redshift(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineRedshift)

	url := os.Getenv("REDSHIFT_URL")
	if url == "" {
		t.Skip("REDSHIFT_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineRedshift.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redshift(name, backend, url, false),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redshift.0.connection_url", url),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redshift.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redshift.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redshift.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redshift(name, backend, url, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "3"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.2", "engineering"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.1", "BAZQUX"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "redshift.0.connection_url", url),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "redshift.0.max_open_connections", "3"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "redshift.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "redshift.0.max_connection_lifetime", "0"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_invalid_plugin(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-db")
	pluginName := name + "-plugin"
	config := fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  plugin_name = "%s"
  redshift {
      max_open_connections = 3
  }
}`, name, name, pluginName)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: config,
				ExpectError: regexp.MustCompile(
					fmt.Sprintf("unsupported database plugin name %q, must begin with one of:", pluginName)),
			},
		},
	})
}

func testAccDatabaseSecretBackendConnectionCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_database_secret_backend_connection" {
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
			return fmt.Errorf("connection %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccDatabaseSecretBackendConnectionConfig_cassandra(name, path, host, username, password, timeout string) string {
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
    protocol_version = 4
    connect_timeout = %s
  }
}
`, path, name, host, username, password, timeout)
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

func testAccDatabaseSecretBackendConnectionConfig_import(name, path, connURL, userTempl string) string {
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

func testAccDatabaseSecretBackendConnectionConfig_influxdb(name, path, host, port, username, password string) string {
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
    port     = "%s"
    username = "%s"
    password = "%s"
    tls      = false
  }
}
`, path, name, host, port, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_couchbase(name, path, host1, username, password, base64PEM string) string {
	var tlsConfig string
	if base64PEM != "" {
		tlsConfig = fmt.Sprintf(`
    tls          = true
    insecure_tls = true
    base64_pem   = "%s"
`, base64PEM)
	}

	config := fmt.Sprintf(`
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
    hosts        = ["%s"]
    username     = "%s"
    password     = "%s"
    bucket_name  = "travel-sample"
%s
  }
}
`, path, name, host1, username, password, tlsConfig)

	return config
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

func testAccDatabaseSecretBackendConnectionConfig_elasticsearchUpdated(name, path, host, username, password, usernameTemplate string) string {
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
	insecure = true
	username_template = %q
	tls_server_name = "test"
  }
}
`, path, name, host, username, password, usernameTemplate)
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

func testAccDatabaseSecretBackendConnectionConfig_mssql(name, path, pluginName string, parsedURL *url.URL, containedDB bool) string {
	var config string
	password, _ := parsedURL.User.Password()

	if containedDB {
		config = `
  mssql {
    connection_url   = "%s"
    username         = "%s"
    password		 = "%s"
    disable_escaping = true
    contained_db     = true
  }`
	} else {
		config = `
  mssql {
	connection_url   = "%s"
    username         = "%s"
    password		 = "%s"
    disable_escaping = true
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
`, path, pluginName, name, fmt.Sprintf(config, parsedURL.String(), parsedURL.User.Username(), password))

	return result
}

func testAccDatabaseSecretBackendConnectionConfig_mysql(name, path, connURL, username, password string) string {
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
      username       = "%s"
      password       = "%s"
  }
}
`, path, name, connURL, username, password)
}

func testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, path, connURL, username, password string, connLifetime int) string {
	config := fmt.Sprintf(`
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
	  username       = "%s"
      password       = "%s"
	  max_connection_lifetime = "%d"
  }
}
`, path, name, connURL, username, password, connLifetime)

	return config
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

func testAccDatabaseSecretBackendConnectionConfig_mysql_aurora_tls(name, path, connURL, password, tls_ca, tls_certificate_key string) string {
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
	config := fmt.Sprintf(`
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
	  username 				  = "%s"
	  password 				  = "%s"
  }
}
`, path, name, connURL, connLifetime, username, password)

	return config
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_rds(name, path, connURL, username, password string) string {
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
	  username       = "%s"
	  password       = "%s"
  }
}
`, path, name, connURL, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_aurora(name, path, connURL, username, password string) string {
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
	  username       = "%s"
	  password       = "%s"
  }
}
`, path, name, connURL, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_legacy(name, path, connURL, username, password string) string {
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
	  username       = "%s"
	  password       = "%s"
  }
}
`, path, name, connURL, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_cloud(name, path, connURL, authType, serviceAccountJSON string) string {
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
	  connection_url       = "%s"
	  auth_type            = "%s"
	  service_account_json = "%s"
  }
}
`, path, name, connURL, authType, serviceAccountJSON)
}

func testAccDatabaseSecretBackendConnectionConfig_postgresql(name, path, userTempl, username, password, openConn, idleConn, maxConnLifetime string, parsedURL *url.URL) string {
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
      connection_url          = "%s"
      max_open_connections    = "%s"
      max_idle_connections    = "%s"
      max_connection_lifetime = "%s"
      username                = "%s"
      password                = "%s"
      username_template       = "%s"
      disable_escaping        = true
  }
}
`, path, name, parsedURL.String(), openConn, idleConn, maxConnLifetime, username, password, userTempl)
}

func testAccDatabaseSecretBackendConnectionConfig_postgresql_reset_optional_values(name, path string, parsedURL *url.URL) string {
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
	  connection_url    = "%s"
  }
}
`, path, name, parsedURL.String())
}

func testAccDatabaseSecretBackendConnectionConfig_postgresql_tls(name, path, tlsCA, tlsCert, privateKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  verify_connection = false

  postgresql {
	connection_url = "postgresql://{{username}}:{{password}}@localhost:5432/postgres?sslmode=verify-full"
	username       = "user1"

	tls_ca          = %q
	tls_certificate = %q
	private_key     = %q
  }
}
`, path, name, tlsCA, tlsCert, privateKey)
}

func testAccDatabaseSecretBackendConnectionConfig_postgres_cloud(name, path, connURL, authType, serviceAccountJSON string) string {
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
      connection_url       = "%s"
		auth_type            = "%s"
		service_account_json = "%s"
  }
}
`, path, name, connURL, authType, serviceAccountJSON)
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

func testAccDatabaseSecretBackendConnectionConfig_redis(name, path, host, port, username, password, allowedRoles string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}
`, path)

	config += fmt.Sprintf(`
resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = [%q]
  redis {
    	host = "%s"
    	port = "%s"
		username = "%s"
		password = "%s"
  }
}`, name, allowedRoles, host, port, username, password)

	return config
}

func testAccDatabaseSecretBackendConnectionConfig_redis_elasticache(name, path, connURL string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}
`, path)

	config += fmt.Sprintf(`
resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["*"]
  redis_elasticache {
    url = "%s"
  }
}`, name, connURL)

	return config
}

func testAccDatabaseSecretBackendConnectionConfig_redshift(name, path, connURL string, isUpdate bool) string {
	config := fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}
`, path)

	if !isUpdate {
		config += fmt.Sprintf(`
resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]
  redshift {
	  connection_url = "%s"
  }
}`, name, connURL)
	} else {
		config += fmt.Sprintf(`
resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["dev", "prod", "engineering"]
  root_rotation_statements = ["FOOBAR", "BAZQUX"]
  redshift {
	  connection_url = "%s"
      max_open_connections = 3
  }
}`, name, connURL)
	}

	return config
}

func newMySQLConnection(t *testing.T, connURL string, username string, password string) *sql.DB {
	mysqlURL := connURL
	runsInContainer := os.Getenv("RUNS_IN_CONTAINER") == "true"
	if !runsInContainer {
		mysqlURL = "{{username}}:{{password}}@tcp(localhost:3306)/"
	}

	dbURL := dbutil.QueryHelper(mysqlURL, map[string]string{
		"username": username,
		"password": password,
	})

	db, err := sql.Open("mysql", dbURL)
	if err != nil {
		t.Fatal(err)
	}

	return db
}

func createMySQLUser(t *testing.T, db *sql.DB, username string, password string) {
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

func MaybeSkipDBTests(t *testing.T, engine *dbEngine) {
	// require TF_ACC to be set
	testutil.SkipTestAcc(t)

	envVars := []string{"SKIP_DB_TESTS"}
	for _, e := range dbEngines {
		if e == engine {
			envVars = append(envVars, envVars[0]+"_"+strings.ToUpper(engine.name))
			break
		}
	}
	testutil.SkipTestEnvSet(t, envVars...)
}

func Test_dbEngine_GetPluginName(t *testing.T) {
	type fields struct {
		name              string
		defaultPluginName string
	}
	type args struct {
		d      *schema.ResourceData
		prefix string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "default",
			fields: fields{
				name:              "foo",
				defaultPluginName: "foo-database-plugin",
			},
			args: args{
				d: schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"plugin_name": {
							Type:     schema.TypeString,
							Required: false,
						},
					},
					map[string]interface{}{},
				),
			},
			want: "foo-database-plugin",
		},
		{
			name: "set",
			fields: fields{
				name: "foo",
			},
			args: args{
				d: schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"plugin_name": {
							Type:     schema.TypeString,
							Required: false,
						},
					},
					map[string]interface{}{
						"plugin_name": "baz-qux",
					},
				),
			},
			want: "baz-qux",
		},
		{
			name: "default-prefixed",
			fields: fields{
				name:              "foo",
				defaultPluginName: "foo" + dbPluginSuffix,
			},
			args: args{
				prefix: "foo.0.",
				d: schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"foo": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"plugin_name": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
								},
							},
						},
					},
					map[string]interface{}{},
				),
			},
			want: "foo" + dbPluginSuffix,
		},
		{
			name: "set-prefixed",
			fields: fields{
				name: "foo",
			},
			args: args{
				prefix: "foo.0.",
				d: schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"foo": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"plugin_name": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
								},
							},
						},
					},
					map[string]interface{}{
						"foo": []interface{}{
							map[string]interface{}{
								"plugin_name": "baz-qux",
							},
						},
					},
				),
			},
			want: "baz-qux",
		},
		{
			name: "fail",
			fields: fields{
				name: "fail",
			},
			args: args{
				d: schema.TestResourceDataRaw(
					t,
					map[string]*schema.Schema{
						"plugin_name": {
							Type:     schema.TypeString,
							Required: false,
						},
					},
					map[string]interface{}{},
				),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &dbEngine{
				name:              tt.fields.name,
				defaultPluginName: tt.fields.defaultPluginName,
			}

			got, err := i.GetPluginName(tt.args.d, tt.args.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPluginName() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if got != tt.want {
				t.Errorf("GetPluginName() expected %v, actual %v", tt.want, got)
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
			want:    dbEngineMSSQL,
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

func Test_getDBEngineFromResp(t *testing.T) {
	tests := []struct {
		name      string
		engines   []*dbEngine
		r         *api.Secret
		want      *dbEngine
		expectErr error
	}{
		{
			name: "basic",
			engines: []*dbEngine{
				{
					name:              "foo",
					defaultPluginName: "foo" + dbPluginSuffix,
				},
			},
			r: &api.Secret{
				Data: map[string]interface{}{
					"plugin_name": "foo-custom",
				},
			},
			want: &dbEngine{
				name:              "foo",
				defaultPluginName: "foo" + dbPluginSuffix,
			},
		},
		{
			name: "basic-aliased",
			engines: []*dbEngine{
				{
					name:              "foo",
					defaultPluginName: "foo" + dbPluginSuffix,
					pluginAliases:     []string{"baz-biff"},
				},
			},
			r: &api.Secret{
				Data: map[string]interface{}{
					"plugin_name": "baz-biff",
				},
			},
			want: &dbEngine{
				name:              "foo",
				defaultPluginName: "foo" + dbPluginSuffix,
				pluginAliases:     []string{"baz-biff"},
			},
		},
		{
			name: "variant",
			engines: []*dbEngine{
				{
					name:              "foo",
					defaultPluginName: "foo" + dbPluginSuffix,
				},
				{
					name:              "foo-variant",
					defaultPluginName: "foo-variant" + dbPluginSuffix,
				},
				{
					name:              "foo-variant-1",
					defaultPluginName: "foo-variant-1" + dbPluginSuffix,
				},
			},
			r: &api.Secret{
				Data: map[string]interface{}{
					"plugin_name": "foo-variant-custom",
				},
			},
			want: &dbEngine{
				name:              "foo-variant",
				defaultPluginName: "foo-variant" + dbPluginSuffix,
			},
		},
		{
			name: "variant-aliased",
			engines: []*dbEngine{
				{
					name:              "foo",
					defaultPluginName: "foo" + dbPluginSuffix,
					pluginAliases:     []string{"baz-biff"},
				},
				{
					name:              "foo-variant",
					defaultPluginName: "foo-variant" + dbPluginSuffix,
					pluginAliases:     []string{"baz-biff-variant"},
				},
				{
					name:              "foo-variant-1",
					defaultPluginName: "foo-variant-1" + dbPluginSuffix,
					pluginAliases:     []string{"baz-biff-variant-1"},
				},
			},
			r: &api.Secret{
				Data: map[string]interface{}{
					"plugin_name": "baz-biff-variant",
				},
			},
			want: &dbEngine{
				name:              "foo-variant",
				defaultPluginName: "foo-variant" + dbPluginSuffix,
				pluginAliases:     []string{"baz-biff-variant"},
			},
		},
		{
			name: "unsupported",
			engines: []*dbEngine{
				{
					name:              "foo",
					defaultPluginName: "foo" + dbPluginSuffix,
				},
			},
			r: &api.Secret{
				Data: map[string]interface{}{
					"plugin_name": "bar-custom",
				},
			},
			want:      nil,
			expectErr: fmt.Errorf("no supported database engines found for plugin %q", "bar-custom"),
		},
		{
			name: "invalid-empty-prefix",
			engines: []*dbEngine{
				{
					name: "foo",
				},
			},
			r: &api.Secret{
				Data: map[string]interface{}{
					"plugin_name": "bar-custom",
				},
			},
			want: nil,
			expectErr: fmt.Errorf(
				"empty plugin prefix, no default plugin name set for dbEngine %q", "foo"),
		},
		{
			name: "invalid-empty-plugin-name",
			engines: []*dbEngine{
				{
					name:              "foo",
					defaultPluginName: "foo" + dbPluginSuffix,
				},
			},
			r: &api.Secret{
				Data: map[string]interface{}{
					"plugin_name": "",
				},
			},
			want:      nil,
			expectErr: fmt.Errorf(`invalid response data, "plugin_name" is empty`),
		},
		{
			name: "invalid-data",
			r: &api.Secret{
				Data: map[string]interface{}{},
			},
			want:      nil,
			expectErr: fmt.Errorf(`invalid response data, missing "plugin_name"`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getDBEngineFromResp(tt.engines, tt.r)
			if tt.expectErr != nil {
				if !reflect.DeepEqual(tt.expectErr, err) {
					t.Errorf("getDBEngineFromResp() expected error = %v, actual %v", tt.expectErr, err)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getDBEngineFromResp() got = %v, want %v", got, tt.want)
			}
		})
	}
}

const testPostgresCACert = `-----BEGIN CERTIFICATE-----
MIIE2jCCAsKgAwIBAgIBATANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDEwJjYTAe
Fw0yNDA3MTIyMDEzMzhaFw0yNjAxMTIyMDIzMzdaMA0xCzAJBgNVBAMTAmNhMIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzd6h6kI5Z3ofQzV5HiKL+uge
hr8AeCywNBUAQ8yX97HKLPYMw2HQFAx9mMIiW1EbwfMb5NYY6blyyyUfZAwzIDzq
IrKwGSa//bS2mO19N5oQdy0w+S+Xo55tsDq0C1hNZf7TOJ/lVOi+Ot68OXqLhmTa
TYrkdYb33kanYVV5IyMgAgGA6w78gJPLKKe57CKe4oq2bU7jPANxu00TthRNL51c
xucGYJCRkeqK7F6MSxXXS1Xv73mh4uTiFYxwsHbgTKW5LAADWWMCwtgjP1ZSfU1U
0BGSyh/fVl1gQIjPCbGp+lSO+eYNhC+/42hvi//y0wH4cv0LwssHZKltDq4pEFwZ
WH8iX6gXoo6FD8FNNCBaZbBAHwPGUkbtjXVl2xhwA5YAin78YM5a1Sy3ZbfxxN++
msSdMxyVM0I/ctnAF/M8RFLOqf/xAbJf/AaXBvPhJAOqqhqMsi2SF5jc5faUpqRE
eOHJGnfFsl1O/0t4YPly/SDowIatMRe+fYp7E79cBve4R9uMPTH2/wV1xla4s42r
GZRoIkeRNg0dI0eFiBOJL8jDTrm8702a2Blu6E0YfxV+XppooGUVzwd2zl7Gvqnl
cSHx4S5drMEz5WGu6/u/ae712BLBvmBrdU1ta8Fr644AZrrsAIL5plY4wez55+/u
LcDlUkKZ01579eDdQBkCAwEAAaNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB
/wQIMAYBAf8CAQAwHQYDVR0OBBYEFF6gLEwzFMWpqOFkhuPY/mMepy8QMA0GCSqG
SIb3DQEBCwUAA4ICAQCaiOUPCFpJx6fw+Vw/sUxzX/JYyrxiOOrMErM5upw3gErq
pYP6RPZS16lOS0LwXQ9G6c72hgcSf4oBL4C/bCXDX7MtXFaa5INI+Bga+OUM9TtD
zSZ/CWpfmUPY1NJOIqFIfhMVmuzGlxdQXrjT0pKQ/SlEJnNN6A5qFkX7+UBgT7Ii
/D11w+I8VTzVmzkkSKalg0I8TZlXD2ADPA+SEljDB6e6wTJie++uLFjhfc2ssJ4I
ZEkMUg8JOtyVAKlrE+i3YhQFjJuTKezIV9ss6akZb8719/iLPudiPo+4Hd4NrEi6
+VDFsc2bBCO8vLYSDyf8pqzZCG74oIZbmneAM2c4pnbTcm5LsBThVUbvzH1rPZGh
3oB4F/CHeov9BfLCdPRjL1HFlD5zUUmA5gPI2avZL8RKCsX1lO7xXVfQihofMAd1
Fb3Wn5+ECeWCPf6EnuEG6aZWyFiBzDrC4jP628t5Oc38Wi3ZQkyVV4BJP+/9AxoF
Z8o9nMIie9BSNfnbAvxwEThY8Jwc5/azZdHXYUrLDA6bcsBw77WTI/TiddzqbU4g
yCAn30ML5eJBdp30xw9+pGpFVbUh4vxBVyLC4Yhbcvp9PuZmIKvkruWNSj3zQSnm
avNz7L+OZEENF2qm/XN6WG5UQHbl3VN614k1dsyD54T+LpNmDZ20wFKPH3zmDw==
-----END CERTIFICATE-----`

const testPostgresClientCert = `-----BEGIN CERTIFICATE-----
MIIEMTCCAhmgAwIBAgIQBMMx4O5wAf+ulbCz1EwvAjANBgkqhkiG9w0BAQsFADAN
MQswCQYDVQQDEwJjYTAeFw0yNDA3MTIyMDEzMzhaFw0yNjAxMTIyMDIzMzdaMBEx
DzANBgNVBAMTBmNsaWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALNhfyofmTapjkf7M5bd6UALxVIngdMx0m/LCE5You2OtuuEM4rFDTs4yi2FFIY+
3rT+ibEiw0QYCTJZ+xOv4TQE8lSGxnrIFtVXlwFLq5eeuuY2eMFtevXj5g6bk50/
FQTs2Laq7LRgN8ZoW+Hn6wglbuM+QLIHGBZtVFfgYXVi54FO24MMWqThgIX21Ns6
iA7nbG/00QYlaqGaZX5vd07cdhxo3qwMSqJc2EP7OKLtmwSuGU4CyWOKfuFr7ITl
DObGIqODvIaRBVFjIsJiEER5V5FWyCAbj1f5jREO6rXoBlwsFvUw7PlFHtX5t7RO
JkUajvbsPYFjNDNwk1u4Mo8CAwEAAaOBiDCBhTAOBgNVHQ8BAf8EBAMCA7gwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBTnlzQEFsMsV3EM
v52+eD/GsjMvqTAfBgNVHSMEGDAWgBReoCxMMxTFqajhZIbj2P5jHqcvEDAUBgNV
HREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggIBAMm6bto3Tti9iMS/
kRpDJ74oIAKybm313va7w85qqxa5wDHY5MAr9qWL/tNUQlzfgsfOrLbXxgVZBjAn
1raxZaBQ5aclmTYKdJRmXAPzcYTu0YV/L3zg2ZX3Rds3M10u1BSxhXK4vTS6VH+K
d3BZF3uQ0pRd49PERTdb+M5l4y/TV+pmgEsDYarLjAoS4WVBXe3FM/RMYjNQJIae
baLCf87G7G/WMtmunW+PmL2pKDlmbkENoSULmX1IQ2CxotdYfI8IJWDE3nKzufzR
X/1mfAksgsSHH4qTUXQFARoGwVaz04pe+E6R0QbgZKWIhhPF+PX99Jm+Uc7s7e7+
u4E76SOfKXfzuB2sfJlR4BxJnVxxrmJVzBRC7ENwXJ2kTfL6PwLT1xUIu/VtJf7N
YnXYx7Is8VVJ7oTCrA1k5tCuPv0AV3SnPq/YzhpUgiWI6sAAtv5GshVETSWta0Bh
XKkRkRK3ubxD7yPhEWypubHY2Nutdj05erBz7FslGvSoPwJrlroLQbwb0fOlHvFA
klHpzMyNSttmDa6S93wGD7U44C+8kMJUZGT3fy3CFvJacvpHdsNKKHhNEgBn+zmG
IRrNQZaXS3XsmjyczI7SETRlYABq644LZlFOXkX4Gj4YG6mkznlB9sYp1OLu34Xn
4Y1FHwnTAcoTwkEPiki3oChg0ndz
-----END CERTIFICATE-----`

const testPostgresClientKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs2F/Kh+ZNqmOR/szlt3pQAvFUieB0zHSb8sITlii7Y6264Qz
isUNOzjKLYUUhj7etP6JsSLDRBgJMln7E6/hNATyVIbGesgW1VeXAUurl5665jZ4
wW169ePmDpuTnT8VBOzYtqrstGA3xmhb4efrCCVu4z5AsgcYFm1UV+BhdWLngU7b
gwxapOGAhfbU2zqIDudsb/TRBiVqoZplfm93Ttx2HGjerAxKolzYQ/s4ou2bBK4Z
TgLJY4p+4WvshOUM5sYio4O8hpEFUWMiwmIQRHlXkVbIIBuPV/mNEQ7qtegGXCwW
9TDs+UUe1fm3tE4mRRqO9uw9gWM0M3CTW7gyjwIDAQABAoIBAQCf5IsGUC4w1EhY
Dyj4FIwiI5vaVA7b4vAR6CdaNpXcLLcODcQnsOfPXxqQIqyd0RKQwMaZV0Q4wTgJ
Yr1z2fViefpLr+rhbNM1jaKza/Di8IDmTa2rtNvCrEbXxIN6yc0Bm+C8SnU9fvqY
Z1NndWNB2qQR+N6QEdS9wOxKfF5C08y9Z3B2xoM2HpeYYW4WEJezMvcDGtDp152p
tN/z8sLKca5doFLwIUiGuJ3g4a5048R9MyEP7bg8g/LAtas4jmOx9xIISRt2i6LJ
ESszY5yy09K06o+IMKWSTDE1GD6o90wEuGDzF6fMNFxRgqVwAVsIaOO9ZRmIa8fV
yyw07MnhAoGBAOG/VXK7AFqfrMLPJY66WX1Az8mLP+uEVv/bfAsnheRNgMD5v3RE
0MgAnx7BAud4O9x4Ej3suNeEiDr4Ukg74CHVKWZACkcTgjY2rg023bwq9slml61E
8XQDgd1D4EELAJAjIldc0rzQ8YTSJ3xBVp5KL+hl1CFPxpEuFhYS7dURAoGBAMtr
edUwge1ti3NCW615RWyDbstvAOlcTyT/a0JViIH7zcZg20ZaQop9PYyGdu/19ha7
8G32flWVqoWf2lBJ+ewG5ykHPEh+O3RLv+3cZs3+0c+fN70PCovsnN5C4BbmR6ls
5FV6/sTJqgN9BJN+wHV1Dj4wMHwWzdXqDUKnPw2fAoGBANsz4+/8/zIAPEwJwuld
r8m85kdI7K9vmN7mrANUxGFUlIJNwIdQzv52BAxj1MMYb9/7w5LXywCS04mXWKaF
ZXTUvFdqNdCgc97ap5VzQkoV2f7knMGF4YMKaM6GuznNSiWryAvWuVbY+LxFKEwy
Ub5wQSbDwgD6qtCMVKvog4JRAoGAcXmoAhxILnmQdCCNYc0nxCvhj4yBtqwu3lW5
sMxkFRaxqLt5Ntq9CeJphk2wZZYQzIfUzJLX0Mhn0pjkwSszRs5m/0UxBMOeSPbE
v1zW4I0I38hS4J1WZc39iCNIPJ4DVekPyvuMyZwxwjZoahsoI53D7z8UnPRfqLgi
447GpsMCgYBnNiNlMvl4UqkZ83mJsqBwPhM3o3jPgS9OHk+nKjRws19lLUuRXCxy
a/0qa6m6iLDrh6oyVXsKlRgsePBl7jUjP3HZTalWpX8+HFbVYIPN3mU50qgjR/uF
lHWczW8tCg9aF3oBqvxt8WV/TU4oV4amunSkbD9HzqcnOuj1fGcZ9w==
-----END RSA PRIVATE KEY-----`
