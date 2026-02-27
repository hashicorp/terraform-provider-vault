// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
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
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				// Always include skip_static_role_import_rotation in config - Vault ignores unknown fields on < 1.19
				// The testAccCheckSkipStaticRoleImportRotation helper handles version-aware assertion
				Config: testAccDatabaseSecretBackendConnectionConfig_import(name, backend, connURL, userTempl, true),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "plugin_name", pluginName),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "test-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "true"),
				),
			},
			{
				ResourceName:            testDefaultDatabaseSecretBackendResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "postgresql.0.connection_url", consts.FieldSkipStaticRoleImportRotation},
			},
		},
	})
}

// TestAccDatabaseSecretBackendConnection_cassandra tests cassandra DB connection for default values
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_cassandra(name, backend, host, username, password, "5", false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.tls_server_name", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.local_datacenter", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.socket_keep_alive", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.consistency", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.username_template", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "cassandra-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
		},
	})
}

// TestAccDatabaseSecretBackendConnection_cassandraProtocol tests cassandra DB connection when optional fields are ommitted
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.protocol_version", "4"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.connect_timeout", "5"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.skip_verification", "false"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.tls_server_name", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.local_datacenter", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.socket_keep_alive", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.consistency", ""),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.username_template", ""),
				),
			},
		},
	})
}

// TestAccDatabaseSecretBackendConnection_cassandra_invalidFields tests cassandra DB connection errors when wrong values are provided
func TestAccDatabaseSecretBackendConnection_cassandra_invalidFields(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineCassandra)

	values := testutil.SkipTestEnvUnset(t, "CASSANDRA_HOST")
	host := values[0]
	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccDatabaseSecretBackendConnectionConfig_cassandra_invalidFields(name, backend, host, username, password, "tls_server_name"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|tls_server_name`),
			},
			{
				Config:      testAccDatabaseSecretBackendConnectionConfig_cassandra_invalidFields(name, backend, host, username, password, "local_datacenter"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|local_datacenter|required|empty`),
			},
			{
				Config:      testAccDatabaseSecretBackendConnectionConfig_cassandra_invalidFields(name, backend, host, username, password, "socket_keep_alive"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|socket_keep_alive|must be|positive`),
			},
			{
				Config:      testAccDatabaseSecretBackendConnectionConfig_cassandra_invalidFields(name, backend, host, username, password, "consistency"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|consistency|unsupported`),
			},
			{
				Config:      testAccDatabaseSecretBackendConnectionConfig_cassandra_invalidFields(name, backend, host, username, password, "username_template"),
				ExpectError: regexp.MustCompile(`(?i)invalid|error|username_template|template`),
			},
		},
	})
}

// TestAccDatabaseSecretBackendConnection_cassandra_customFields tests cassandra DB connection when tls=true and proper values given to fields
func TestAccDatabaseSecretBackendConnection_cassandra_customFields(t *testing.T) {
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
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_cassandra_customFields(name, backend, host, username, password),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, dbEngineCassandra.DefaultPluginName(),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.tls_server_name", "cassandra-server"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.local_datacenter", "datacenter1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.socket_keep_alive", "30"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.consistency", "LOCAL_QUORUM"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.username_template", "vault_{{.RoleName}}_{{.DisplayName}}_{{random 10}}"),
				),
			},
		},
	})
}

// TestAccDatabaseSecretBackendConnection_cassandra_customFieldsNoTLS tests cassandra DB connection when tls=false and proper values given to fields
func TestAccDatabaseSecretBackendConnection_cassandra_customFieldsNoTLS(t *testing.T) {
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
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_cassandra_customFieldsNoTLS(name, backend, host, username, password),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, dbEngineCassandra.DefaultPluginName(),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.tls", "false"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.local_datacenter", "datacenter1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.socket_keep_alive", "30"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.consistency", "LOCAL_QUORUM"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "cassandra.0.username_template", "vault_{{.RoleName}}_{{.DisplayName}}_{{random 10}}"),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
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

	publicKey, privateKey, projectID := values[0], values[1], values[2]

	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineMongoDBAtlas.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	usernameTemplate := "{{.DisplayName}}"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mongodbatlas(name, backend, publicKey, privateKey, projectID, usernameTemplate),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodbatlas.0.username_template", usernameTemplate),
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
	writeConcern := `{"wmode": "majority", "wtimeout": 5000}`
	pluginName := dbEngineMongoDB.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mongodb(name, backend, writeConcern, connURL, false),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodb.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodb.0.write_concern", writeConcern),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "mongo-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mongodb_tls(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	writeConcern := `{"wmode": "majority", "wtimeout": 5000}`
	pluginName := dbEngineMongoDB.DefaultPluginName()

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mongodb_tls(name, backend, writeConcern, testMongoDBCACert, testMongoDBClientCertKey),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodb.0.tls_ca", testMongoDBCACert),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodb.0.tls_certificate_key", testMongoDBClientCertKey),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mongodb.0.write_concern", writeConcern),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mssql(name, backend, pluginName, parsedURL, false, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "mssql-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mssql(name, backend, pluginName, parsedURL, false, false),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_cloud(name, backend, connURL, "gcp_iam", saJSON, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "mysql.0.service_account_json", saJSON),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "mysql-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql(name, backend, connURL, username, password, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "mysql-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql_rds(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t,
		"MYSQL_CONNECTION_URL", "MYSQL_CONNECTION_USERNAME", "MYSQL_CONNECTION_PASSWORD")
	connURL, username, password := values[0], values[1], values[2]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_rds(name, backend, connURL, username, password, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "mysql-rds-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql_aurora(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t,
		"MYSQL_CONNECTION_URL", "MYSQL_CONNECTION_USERNAME", "MYSQL_CONNECTION_PASSWORD")
	connURL, username, password := values[0], values[1], values[2]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_aurora(name, backend, connURL, username, password, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "mysql-legacy-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql_legacy(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineMySQL)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t,
		"MYSQL_CONNECTION_URL", "MYSQL_CONNECTION_USERNAME", "MYSQL_CONNECTION_PASSWORD")
	connURL, username, password := values[0], values[1], values[2]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_legacy(name, backend, connURL, username, password, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "mysql-legacy-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
		},
	})
}

func testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName string, fs ...resource.TestCheckFunc) resource.TestCheckFunc {
	funcs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldName, name),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldBackend, backend),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPluginName, pluginName),
	}
	funcs = append(funcs, fs...)

	return resource.ComposeAggregateTestCheckFunc(funcs...)
}

// testAccCheckSkipStaticRoleImportRotation checks the skip_static_role_import_rotation attribute.
// This field is only available in Vault Enterprise 1.19+, so the check is skipped for
// non-Enterprise or older versions.
func testAccCheckSkipStaticRoleImportRotation(resourceName, expected string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		meta := testProvider.Meta().(*provider.ProviderMeta)
		curVer := meta.GetVaultVersion()
		if curVer == nil {
			return fmt.Errorf("vault version not set on %T", meta)
		}
		// skip_static_role_import_rotation is only available in Vault Enterprise 1.19+
		if curVer.LessThan(provider.VaultVersion119) || !meta.IsEnterpriseSupported() {
			return nil
		}
		return resource.TestCheckResourceAttr(resourceName, consts.FieldSkipStaticRoleImportRotation, expected)(s)
	}
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, backend, connURL, username, password, 0, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "mysql-update-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, backend, connURL, username, password, 10, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "mysql-update-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
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

func TestAccDatabaseSecretBackendConnection_oracle(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineOracle)

	// ORACLE_PLUGIN_NAME is required as not built-in plugin (already installed or installed during test, cf below)
	//  if ORACLE_PLUGIN_INSTALL=true
	//    plugin ORACLE_PLUGIN_NAME will be add to the catalog using vault_plugin resources:
	//    resource "vault_plugin" "plugin" {
	//       type    = "database"
	//       name    = "$ORACLE_PLUGIN_NAME"
	//       command = "$ORACLE_PLUGIN_NAME"
	//       version = "$ORACLE_PLUGIN_VERSION"
	//       sha256  = "$ORACLE_PLUGIN_SHA"
	//    }
	//
	//  To work, it requires the oracle binary plugin in Vault plugin directory
	//
	values := testutil.SkipTestEnvUnset(t, "ORACLE_CONNECTION_URL", "ORACLE_CONNECTION_USERNAME", "ORACLE_CONNECTION_PASSWORD", "ORACLE_PLUGIN_NAME", "ORACLE_PLUGIN_INSTALL")
	connURL, username, password, pluginName, pluginInstall := values[0], values[1], values[2], values[3], values[4]

	var pluginVersion, pluginSHA string
	if pluginInstall == "true" {
		values2 := testutil.SkipTestEnvUnset(t, "ORACLE_PLUGIN_VERSION", "ORACLE_PLUGIN_SHA")
		pluginVersion, pluginSHA = values2[0], values2[1]
	}

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "1"),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "*"),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "oracle.0.connection_url", connURL),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "oracle.0.username", username),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "oracle.0.password", password),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "oracle-policy"),
		testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
	}

	// Only check plugin version when installing the plugin
	if pluginInstall == "true" {
		checks = append(checks, resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPluginVersion, pluginVersion))
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_oracle(name, backend, pluginName, connURL, username, password, "*", pluginInstall, pluginVersion, pluginSHA, false),
				Check:  testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName, checks...),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql(name, backend, userTempl, username, password, maxOpenConnections, maxIdleConnections, maxConnLifetime, parsedURL, false),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.password_authentication", "password"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_open_connections", maxOpenConnections),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_idle_connections", maxIdleConnections),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.max_connection_lifetime", maxConnLifetime),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.password", password),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.disable_escaping", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.username_template", userTempl),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "postgres-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "postgres-policy"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql_password_authentication(name, backend, parsedURL),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.password_authentication", "scram-sha-256"),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
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

func TestAccDatabaseSecretBackendConnection_postgresql_rootlessConfig(t *testing.T) {
	resourceName := "vault_database_secret_backend_connection.test"
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEnginePostgres.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion118)
		},
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql_rootless(name, backend),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(resourceName, "postgresql.0.self_managed", "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, ""),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
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

// TestAccDatabaseSecretBackendConnection_postgresql_automatedRootRotation tests that Automated
// Root Rotation parameters are compatible with the DB Secrets Backend Connection resource
func TestAccDatabaseSecretBackendConnection_postgresql_automatedRootRotation(t *testing.T) {
	MaybeSkipDBTests(t, dbEnginePostgres)

	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	resourceName := "vault_database_secret_backend_connection.test"
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
				Config: testAccDatabaseSecretBackendConnectionConfig_postgres_automatedRootRotation(name, backend, connURL, "", 10, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			// zero-out rotation_period
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgres_automatedRootRotation(name, backend, connURL, "*/20 * * * *", 0, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "120"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * *"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				Config:      testAccDatabaseSecretBackendConnectionConfig_postgres_automatedRootRotation(name, backend, connURL, "", 30, 120, false),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			// zero-out rotation_schedule and rotation_window
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgres_automatedRootRotation(name, backend, connURL, "", 30, 0, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "verify_connection", "postgresql.0.connection_url"),
		},
	})
}

// TestAccDatabaseSecretBackendConnection_postgresql_writeOnly ensures
// write-only attribute `password_wo` works as expected
//
// The test creates users in a Postgres DB
// To run locally you will need to set the following env vars:
//   - POSTGRES_URL_TEST
//   - POSTGRES_URL_ROOTLESS
//
// See .github/workflows/build.yml for details.
func TestAccDatabaseSecretBackendConnection_postgresql_password_wo(t *testing.T) {
	MaybeSkipDBTests(t, dbEnginePostgres)

	connURLTestRoot := testutil.SkipTestEnvUnset(t, "POSTGRES_URL_TEST")[0]
	connURLTemplated := testutil.SkipTestEnvUnset(t, "POSTGRES_URL_ROOTLESS")[0]
	username1 := acctest.RandomWithPrefix("user1")
	username2 := acctest.RandomWithPrefix("user2")
	dbName := acctest.RandomWithPrefix("db")
	// create database users
	testutil.CreateTestPGUser(t, connURLTestRoot, username1, "testpassword", testRoleStaticCreate)
	testutil.CreateTestPGUser(t, connURLTestRoot, username2, "testpassword1", testRoleStaticCreate)
	mount := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEnginePostgres.DefaultPluginName()
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql_writeOnly(dbName, mount, connURLTemplated, username1, "testpassword", 1),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(dbName, mount, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "*"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.connection_url", connURLTemplated),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.username", username1),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.password_wo_version", "1"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql_writeOnly(dbName, mount, connURLTemplated, username2, "testpassword1", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testDefaultDatabaseSecretBackendResource, plancheck.ResourceActionUpdate),
					},
				},
				// successful connection to new username guarantees that password_wo was also updated
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(dbName, mount, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "*"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.connection_url", connURLTemplated),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.username", username2),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "postgresql.0.password_wo_version", "2"),
				),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_elasticsearch(name, backend, connURL, username, password, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "elastic-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
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

func TestAccDatabaseSecretBackendConnection_snowflake_userpass(t *testing.T) {
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

	config := testAccDatabaseSecretBackendConnectionConfig_snowflake_userpass(name, backend, connURL, username, password, userTempl)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
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

func TestAccDatabaseSecretBackendConnection_snowflake_keypair(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineSnowflake)

	// TODO: make these fatal once we auto provision the required test infrastructure.
	values := testutil.SkipTestEnvUnset(t, "SNOWFLAKE_URL")
	connURL := values[0]

	username := os.Getenv("SNOWFLAKE_USERNAME")
	privateKey := os.Getenv("SNOWFLAKE_PRIVATE_KEY")
	backend := acctest.RandomWithPrefix("tf-test-db")
	pluginName := dbEngineSnowflake.DefaultPluginName()
	name := acctest.RandomWithPrefix("db")
	userTempl := "{{.DisplayName}}"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		},
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_snowflake_keypair(name, backend, connURL, username, userTempl, privateKey, "1", false),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.private_key_wo_version", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.username_template", userTempl),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "snowflake-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_snowflake_keypair(name, backend, connURL, username+"new", userTempl, privateKey, "2", false),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testDefaultDatabaseSecretBackendResource, plancheck.ResourceActionUpdate),
					},
				},
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.username", username+"new"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "snowflake.0.private_key_wo_version", "2"),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redis(name, backend, host, port, username, password, "*", false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "redis-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
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
				Config: testAccDatabaseSecretBackendConnectionConfig_redis(name, backend, host, port, username, password, "foobar", false),
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

func TestAccDatabaseSecretBackendConnection_redis_externalPlugin(t *testing.T) {
	MaybeSkipDBTests(t, dbEngineRedis)

	// REDIS_PLUGIN_NAME is required as not built-in plugin (already installed or installed during test, cf below)
	//  if REDIS_PLUGIN_INSTALL=true
	//    plugin REDIS_PLUGIN_NAME will be add to the catalog using vault_plugin resources:
	//    resource "vault_plugin" "plugin" {
	//       type    = "database"
	//       name    = "$REDIS_PLUGIN_NAME"
	//       command = "$REDIS_PLUGIN_NAME"
	//       version = "$REDIS_PLUGIN_VERSION"
	//       sha256  = "$REDIS_PLUGIN_SHA"
	//    }
	//
	//  To work, it requires the redis binary plugin in Vault plugin directory
	//
	values := testutil.SkipTestEnvUnset(t, "REDIS_HOST", "REDIS_PORT", "REDIS_USERNAME", "REDIS_PASSWORD", "REDIS_PLUGIN_NAME", "REDIS_PLUGIN_INSTALL")
	host, port, username, password, pluginName, pluginInstall := values[0], values[1], values[2], values[3], values[4], values[5]

	var pluginVersion, pluginSHA string
	if pluginInstall == "true" {
		values2 := testutil.SkipTestEnvUnset(t, "REDIS_PLUGIN_VERSION", "REDIS_PLUGIN_SHA")
		pluginVersion, pluginSHA = values2[0], values2[1]
	}

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "1"),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "*"),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.host", host),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.port", port),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.username", username),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.password", password),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.tls", "false"),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis.0.insecure_tls", "false"),
		resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "redis-policy"),
		testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
	}

	// Only check plugin version when installing the plugin
	if pluginInstall == "true" {
		checks = append(checks, resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPluginVersion, pluginVersion))
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redis_externalPlugin(name, backend, pluginName, host, port, username, password, "*", pluginInstall, pluginVersion, pluginSHA, false),
				Check:  testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName, checks...),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redis_elasticache(name, backend, url, false),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "*"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "redis_elasticache.0.url", url),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "redis-elasticache-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redshift(name, backend, url, false, false),
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
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, consts.FieldPasswordPolicy, "redshift-policy"),
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_redshift(name, backend, url, true, false),
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

func TestDatabaseEngineNameAndIndexFromPrefix(t *testing.T) {
	testcases := []struct {
		name         string
		prefix       string
		expectedName string
		expectedIdx  string
		wantErr      bool
		expectedErr  string
	}{
		{
			name:         "simple",
			prefix:       "postgresql.0.",
			wantErr:      false,
			expectedName: "postgresql",
			expectedIdx:  "0",
		},
		{
			name:         "complex",
			prefix:       "custom_mssql_db_us-west-2_v2.1.5.",
			wantErr:      false,
			expectedName: "custom_mssql_db_us-west-2_v2.1",
			expectedIdx:  "5",
		},
		{
			name:        "invalid",
			prefix:      "invalid-prefix",
			wantErr:     true,
			expectedErr: "no matches found",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			name, idx, err := databaseEngineNameAndIndexFromPrefix(tc.prefix)
			if tc.wantErr && (err == nil) {
				t.Fatalf("wanted error %v, got nil", tc.wantErr)
			}

			if tc.wantErr && (err.Error() != tc.expectedErr) {
				t.Fatalf("got error %v, wantErr %v", err, tc.wantErr)
			}

			if name != tc.expectedName {
				t.Fatalf("got %s, want %s", name, tc.expectedName)
			}

			if idx != tc.expectedIdx {
				t.Fatalf("got %s, want %s", idx, tc.expectedIdx)
			}
		})
	}
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
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

func testAccDatabaseSecretBackendConnectionConfig_cassandra(name, path, host, username, password, timeout string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
	return fmt.Sprintf(`
	resource "vault_mount" "db" {
		path = "%s"
		type = "database"
	}

	resource "vault_database_secret_backend_connection" "test" {
		backend = vault_mount.db.path
		name = "%s"
		allowed_roles = ["dev", "prod"]
		verify_connection = true
		root_rotation_statements = ["FOOBAR"]
		password_policy = "cassandra-policy"
  		%s

		cassandra {
			hosts = ["%s"]
			username = "%s"
			password = "%s"
			tls = false
			protocol_version = 4
			connect_timeout = %s
			tls_server_name = ""
			local_datacenter = ""
			socket_keep_alive = 0
			consistency = ""
			username_template = ""
		}
	}
	`, path, name, skipStaticLine, host, username, password, timeout)
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
  verify_connection = true
  root_rotation_statements = ["FOOBAR"]

  cassandra {
    hosts = ["%s"]
    username = "%s"
    password = "%s"
    tls = false
    protocol_version = 4
  }
}
`, path, name, host, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_cassandra_invalidFields(name, backend, host, username, password, invalidField string) string {
	// Base configuration with valid values
	config := fmt.Sprintf(`

resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  name    = "%s"
  backend = vault_mount.db.path
  plugin_name = "cassandra-database-plugin"
  allowed_roles = ["dev", "prod"]
  verify_connection = true

  cassandra {
    hosts              = ["%s"]
    port               = 9042
    username           = "%s"
    password           = "%s"
    connect_timeout    = 30`, backend, name, host, username, password)

	// Add the specific invalid field based on the parameter
	switch invalidField {
	case "tls_server_name":
		config += `
    tls                = true
    tls_server_name    = "!!invalid!!"
    insecure_tls       = true`
	case "local_datacenter":
		config += `
    local_datacenter   = ""`
	case "socket_keep_alive":
		config += `
    socket_keep_alive  = -1`
	case "consistency":
		config += `
    consistency        = "INVALID"`
	case "username_template":
		config += `
    username_template  = "{{.Invalid}}"`
	}

	config += `
  }
}
`
	return config
}

func testAccDatabaseSecretBackendConnectionConfig_cassandra_customFields(name, backend, host, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  name    = "%s"
  backend = vault_mount.db.path
  plugin_name = "cassandra-database-plugin"
  allowed_roles = ["dev", "prod"]
  verify_connection = true

  cassandra {
    hosts              = ["%s"]
    port               = 9042
    username           = "%s"
    password           = "%s"
    protocol_version   = 4
    tls                = true
    tls_server_name    = "cassandra-server"
    local_datacenter   = "datacenter1"
    socket_keep_alive  = 30
    consistency        = "LOCAL_QUORUM"
    username_template  = "vault_{{.RoleName}}_{{.DisplayName}}_{{random 10}}"
    insecure_tls       = true
    connect_timeout    = 30
  }
}
`, backend, name, host, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_cassandra_customFieldsNoTLS(name, backend, host, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  name    = "%s"
  backend = vault_mount.db.path
  plugin_name = "cassandra-database-plugin"
  allowed_roles = ["dev", "prod"]
  verify_connection = true

  cassandra {
    hosts              = ["%s"]
    port               = 9042
    username           = "%s"
    password           = "%s"
    protocol_version   = 4
    tls                = false
    tls_server_name    = "cassandra-server"
    local_datacenter   = "datacenter1"
    socket_keep_alive  = 30
    consistency        = "LOCAL_QUORUM"
    username_template  = "vault_{{.RoleName}}_{{.DisplayName}}_{{random 10}}"
    insecure_tls       = false
    connect_timeout    = 30
  }
}
`, backend, name, host, username, password)
}

// testAccDatabaseSecretBackendConnectionConfig_import generates config for PostgreSQL import test.
// When includeSkipStatic is true, includes skip_static_role_import_rotation = true.
// Note: Vault versions < 1.19 ignore this field; version-aware assertions should be used in tests.
func testAccDatabaseSecretBackendConnectionConfig_import(name, path, connURL, userTempl string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "test-policy"
  plugin_name = "postgresql-database-plugin"
  %s

  postgresql {
	  connection_url = "%s"
	  username_template = "%s"
  }
}
`, path, name, skipStaticLine, connURL, userTempl)
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

func testAccDatabaseSecretBackendConnectionConfig_elasticsearch(name, path, host, username, password string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "elastic-policy"
  %s

  elasticsearch {
    url = "%s"
    username = "%s"
    password = "%s"
  }
}
`, path, name, skipStaticLine, host, username, password)
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

func testAccDatabaseSecretBackendConnectionConfig_mongodbatlas(name, path, public_key, private_key, project_id, username_template string) string {
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
	username_template = "%s"
  }
}
`, path, name, public_key, private_key, project_id, username_template)
}

func testAccDatabaseSecretBackendConnectionConfig_mongodb(name, path, writeConcern, connURL string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "mongo-policy"
  %s

  mongodb {
    connection_url = "%s"
    write_concern  = %q
  }
}
`, path, name, skipStaticLine, connURL, writeConcern)
}

func testAccDatabaseSecretBackendConnectionConfig_mongodb_tls(name, path, writeConcern, tlsCA, tlsCertificateKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend          = vault_mount.db.path
  name             = "%s"
  allowed_roles    = ["dev", "prod"]
  verify_connection = false

  mongodb {
    connection_url      = "mongodb://localhost:27017/admin?tls=true"
    write_concern       = %q
    tls_ca              = %q
    tls_certificate_key = %q
  }
}
`, path, name, writeConcern, tlsCA, tlsCertificateKey)
}

func testAccDatabaseSecretBackendConnectionConfig_mssql(name, path, pluginName string, parsedURL *url.URL, containedDB bool, includeSkipStatic bool) string {
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

	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
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
    password_policy = "mssql-policy"
  %s
%s
}
`, path, pluginName, name, skipStaticLine, fmt.Sprintf(config, parsedURL.String(), parsedURL.User.Username(), password))

	return result
}

func testAccDatabaseSecretBackendConnectionConfig_mysql(name, path, connURL, username, password string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "mysql-policy"
  %s

  mysql {
	  connection_url = "%s"
      username       = "%s"
      password       = "%s"
  }
}
`, path, name, skipStaticLine, connURL, username, password)
}

func testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, path, connURL, username, password string, connLifetime int, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "mysql-update-policy"
  %s

  mysql {
	  connection_url = "%s"
	  username       = "%s"
      password       = "%s"
	  max_connection_lifetime = "%d"
  }
}
`, path, name, skipStaticLine, connURL, username, password, connLifetime)

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

func testAccDatabaseSecretBackendConnectionConfig_mysql_rds(name, path, connURL, username, password string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "mysql-rds-policy"
  %s

  mysql_rds {
	  connection_url = "%s"
	  username       = "%s"
	  password       = "%s"
  }
}
`, path, name, skipStaticLine, connURL, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_aurora(name, path, connURL, username, password string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "mysql-legacy-policy"
  %s

  mysql_aurora {
	  connection_url = "%s"
	  username       = "%s"
	  password       = "%s"
  }
}
`, path, name, skipStaticLine, connURL, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_legacy(name, path, connURL, username, password string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "mysql-legacy-policy"
  %s

  mysql_legacy {
	  connection_url = "%s"
	  username       = "%s"
	  password       = "%s"
  }
}
`, path, name, skipStaticLine, connURL, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_cloud(name, path, connURL, authType, serviceAccountJSON string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "mysql-cloud-policy"
  %s

  mysql {
	  connection_url       = "%s"
	  auth_type            = "%s"
	  service_account_json = "%s"
  }
}
`, path, name, skipStaticLine, connURL, authType, serviceAccountJSON)
}

func testAccDatabaseSecretBackendConnectionConfig_oracle(name, path, pluginName, connURL, username, password, allowedRoles, pluginInstall, pluginVersion, pluginSHA string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
	config := fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}
`, path)

	if pluginInstall == "true" {
		config += fmt.Sprintf(`
resource "vault_plugin" "plugin" {
  type    = "database"
  name    = "%s"
  command = "%s"
  version = "%s"
  sha256  = "%s"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  plugin_name = vault_plugin.plugin.name
  plugin_version = "%s"
  name = "%s"
  allowed_roles = [%q]
  password_policy = "oracle-policy"
  %s
  oracle {
    	connection_url = "%s"
		username = "%s"
		password = "%s"
  }
}
`, pluginName, pluginName, pluginVersion, pluginSHA, pluginVersion, name, allowedRoles, skipStaticLine, connURL, username, password)

	} else {

		config += fmt.Sprintf(`
resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  plugin_name = "%s"
  name = "%s"
  allowed_roles = [%q]
  oracle {
    	connection_url = "%s"
		username = "%s"
		password = "%s"
  }
}`, pluginName, name, allowedRoles, connURL, username, password)
	}

	return config
}

func testAccDatabaseSecretBackendConnectionConfig_postgresql(name, path, userTempl, username, password, openConn, idleConn, maxConnLifetime string, parsedURL *url.URL, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "postgres-policy"
  %s
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
`, path, name, skipStaticLine, parsedURL.String(), openConn, idleConn, maxConnLifetime, username, password, userTempl)
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
  password_policy = "postgres-policy"

  postgresql {
	  connection_url    = "%s"
  }
}
`, path, name, parsedURL.String())
}

func testAccDatabaseSecretBackendConnectionConfig_postgresql_password_authentication(name, path string, parsedURL *url.URL) string {
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
  password_policy = "postgres-policy"

  postgresql {
	  connection_url          = "%s"
	  password_authentication = "scram-sha-256"
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

func testAccDatabaseSecretBackendConnectionConfig_postgresql_rootless(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"

  postgresql {
	connection_url = "postgresql://{{username}}:{{password}}@localhost:5432/postgres?sslmode=verify-full"
	self_managed   = true
  }
}
`, path, name)
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

func testAccDatabaseSecretBackendConnectionConfig_postgres_automatedRootRotation(name, path, connURL, schedule string, period, window int, disable bool) string {
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
  rotation_period = "%d"
  rotation_schedule = "%s"
  rotation_window = "%d"
  disable_automated_rotation = %t

  postgresql {
      connection_url       = "%s"
  }
}
`, path, name, period, schedule, window, disable, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_postgresql_writeOnly(name, path, connUrl, username, password string, version int) string {
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
      connection_url          = "%s"
      username                = "%s"
      password_wo             = "%s"
      password_wo_version     = %d
  }
}
`, path, name, connUrl, username, password, version)
}

func testAccDatabaseSecretBackendConnectionConfig_snowflake_userpass(name, path, url, username, password, userTempl string) string {
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

func testAccDatabaseSecretBackendConnectionConfig_snowflake_keypair(name, path, url, username, userTempl, privateKey, privateKeyVersion string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "snowflake-policy"
  %s

  snowflake {
    connection_url = "%s"
    username = "%s"
	 username_template = "%s"
    private_key_wo = <<-EOT
%s
EOT
    private_key_wo_version = "%s"
  }
}
`, path, name, skipStaticLine, url, username, userTempl, privateKey, privateKeyVersion)
}

func testAccDatabaseSecretBackendConnectionConfig_redis(name, path, host, port, username, password, allowedRoles string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "redis-policy"
  %s
  redis {
    	host = "%s"
    	port = "%s"
		username = "%s"
		password = "%s"
  }
}`, name, allowedRoles, skipStaticLine, host, port, username, password)

	return config
}

func testAccDatabaseSecretBackendConnectionConfig_redis_externalPlugin(name, path, pluginName, host, port, username, password, allowedRoles, pluginInstall, pluginVersion, pluginSHA string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
	config := fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}
`, path)

	if pluginInstall == "true" {
		config += fmt.Sprintf(`
resource "vault_plugin" "plugin" {
  type    = "database"
  name    = "%s"
  command = "%s"
  version = "%s"
  sha256  = "%s"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  plugin_name = vault_plugin.plugin.name
  plugin_version = "%s"
  name = "%s"
  allowed_roles = [%q]
  password_policy = "redis-policy"
  %s
  redis {
    	host = "%s"
    	port = "%s"
		username = "%s"
		password = "%s"
  }
}
`, pluginName, pluginName, pluginVersion, pluginSHA, pluginVersion, name, allowedRoles, skipStaticLine, host, port, username, password)

	} else {

		config += fmt.Sprintf(`
resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  plugin_name = "%s"
  name = "%s"
  allowed_roles = [%q]
  password_policy = "redis-policy"
  %s
  redis {
    	host = "%s"
    	port = "%s"
		username = "%s"
		password = "%s"
  }
}`, pluginName, name, allowedRoles, skipStaticLine, host, port, username, password)
	}

	return config
}

func testAccDatabaseSecretBackendConnectionConfig_redis_elasticache(name, path, connURL string, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "redis-elasticache-policy"
  %s
  redis_elasticache {
    url = "%s"
  }
}`, name, skipStaticLine, connURL)

	return config
}

func testAccDatabaseSecretBackendConnectionConfig_redshift(name, path, connURL string, isUpdate bool, includeSkipStatic bool) string {
	skipStaticLine := ""
	if includeSkipStatic {
		skipStaticLine = "skip_static_role_import_rotation = true"
	}
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
  password_policy = "redshift-policy"
  %s
  redshift {
	  connection_url = "%s"
  }
}`, name, skipStaticLine, connURL)
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

const testMongoDBCACert = `-----BEGIN CERTIFICATE-----
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

const testMongoDBClientCertKey = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
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

func TestAccDatabaseSecretBackendConnection_hana(t *testing.T) {
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
		"verify_connection",
		"hana.0.password",
		"hana.0.connection_url",
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_hana(name, backend, connURL, username, password, userTempl),
				Check: testComposeCheckFuncCommonDatabaseSecretBackend(name, backend, pluginName,
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "verify_connection", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "hana.0.connection_url", connURL),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "hana.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "hana.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "hana.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "hana.0.username", username),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "hana.0.disable_escaping", "true"),
					resource.TestCheckResourceAttr(testDefaultDatabaseSecretBackendResource, "hana.0.username_template", userTempl),
					func(s *terraform.State) error {
						client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

						// Validate that the connection can generate credentials through the role
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

						// Revoke the lease to prevent cleanup errors
						if resp.LeaseID != "" {
							err = client.Sys().Revoke(resp.LeaseID)
							if err != nil {
								return fmt.Errorf("error revoking lease: %v", err)
							}
						}

						return nil
					},
				),
			},
			{
				ResourceName:            testDefaultDatabaseSecretBackendResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importIgnoreKeys,
			},
		},
	})
}

func testAccDatabaseSecretBackendConnectionConfig_hana(name, path, connURL, username, password, userTempl string) string {
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

  hana {
    connection_url = "%s"
    username = "%s"
    password = "%s"
    disable_escaping = true
    username_template = "%s"
  }
}

resource "vault_database_secret_backend_role" "test" {
  backend = vault_mount.db.path
  name = "dev"
  db_name = vault_database_secret_backend_connection.test.name
  creation_statements = [
    "CREATE USER {{name}} PASSWORD \"{{password}}\";",
    "GRANT SELECT ON SCHEMA _SYS_BIC TO {{name}};"
  ]
  default_ttl = 3600
  max_ttl = 7200
}
`, path, name, connURL, username, password, userTempl)
}

func TestAccDatabaseSecretBackendConnection_skipStaticRoleImportRotation(t *testing.T) {
	MaybeSkipDBTests(t, dbEnginePostgres)

	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	connURL := values[0]

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
			// skip_static_role_import_rotation is only available in Vault Enterprise
			meta := testProvider.Meta().(*provider.ProviderMeta)
			if !meta.IsEnterpriseSupported() {
				t.Skip("skip_static_role_import_rotation is an Enterprise-only feature")
			}
		},
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with skip_static_role_import_rotation = true
				Config: testAccDatabaseSecretBackendConnectionConfig_skipRotation(name, backend, connURL, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "true"),
				),
			},
			{
				// Step 2: Update to skip_static_role_import_rotation = false (explicit)
				// This tests the SDK v2 bug fix - without GetOkExists, this would fail
				Config: testAccDatabaseSecretBackendConnectionConfig_skipRotation(name, backend, connURL, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
			{
				// Step 3: Remove skip_static_role_import_rotation (should default to false)
				Config: testAccDatabaseSecretBackendConnectionConfig_skipRotation_omitted(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "false"),
				),
			},
			{
				// Step 4: Set back to true to verify toggle works
				Config: testAccDatabaseSecretBackendConnectionConfig_skipRotation(name, backend, connURL, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSkipStaticRoleImportRotation(testDefaultDatabaseSecretBackendResource, "true"),
				),
			},
		},
	})
}

func testAccDatabaseSecretBackendConnectionConfig_skipRotation(name, path, connURL string, skipRotation bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = vault_mount.db.path
  name = "%s"
  allowed_roles = ["*"]
  skip_static_role_import_rotation = %t

  postgresql {
    connection_url = "%s"
  }
}
`, path, name, skipRotation, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_skipRotation_omitted(name, path, connURL string) string {
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
  }
}
`, path, name, connURL)
}
