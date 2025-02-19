// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

type connectionStringConfig struct {
	excludeUsernameTemplate bool
	includeUserPass         bool
	includeDisableEscaping  bool
	isCloud                 bool
}

const (
	dbPluginSuffix = "-database-plugin"
)

var (
	databaseSecretBackendConnectionBackendFromPathRegex = regexp.MustCompile("^(.+)/config/.+$")
	databaseSecretBackendConnectionNameFromPathRegex    = regexp.MustCompile("^.+/config/(.+$)")

	dbEngineCassandra = &dbEngine{
		name:              "cassandra",
		defaultPluginName: "cassandra" + dbPluginSuffix,
	}
	dbEngineCouchbase = &dbEngine{
		name:              "couchbase",
		defaultPluginName: "couchbase" + dbPluginSuffix,
	}

	dbEngineElasticSearch = &dbEngine{
		name:              "elasticsearch",
		defaultPluginName: "elasticsearch" + dbPluginSuffix,
	}
	dbEngineHana = &dbEngine{
		name:              "hana",
		defaultPluginName: "hana" + dbPluginSuffix,
	}
	dbEngineInfluxDB = &dbEngine{
		name:              "influxdb",
		defaultPluginName: "influxdb" + dbPluginSuffix,
	}
	dbEngineMSSQL = &dbEngine{
		name:              "mssql",
		defaultPluginName: "mssql" + dbPluginSuffix,
	}
	dbEngineMongoDB = &dbEngine{
		name:              "mongodb",
		defaultPluginName: "mongodb" + dbPluginSuffix,
	}
	dbEngineMongoDBAtlas = &dbEngine{
		name:              "mongodbatlas",
		defaultPluginName: "mongodbatlas" + dbPluginSuffix,
	}
	dbEngineMySQL = &dbEngine{
		name:              "mysql",
		defaultPluginName: "mysql" + dbPluginSuffix,
	}
	dbEngineMySQLAurora = &dbEngine{
		name:              "mysql_aurora",
		defaultPluginName: "mysql-aurora" + dbPluginSuffix,
	}
	dbEngineMySQLLegacy = &dbEngine{
		name:              "mysql_legacy",
		defaultPluginName: "mysql-legacy" + dbPluginSuffix,
	}
	dbEngineMySQLRDS = &dbEngine{
		name:              "mysql_rds",
		defaultPluginName: "mysql-rds" + dbPluginSuffix,
	}
	dbEnginePostgres = &dbEngine{
		name:              "postgresql",
		defaultPluginName: "postgresql" + dbPluginSuffix,
	}
	dbEngineOracle = &dbEngine{
		name:              "oracle",
		defaultPluginName: "oracle" + dbPluginSuffix,
		pluginAliases:     []string{"vault-plugin-database-oracle"},
	}
	dbEngineSnowflake = &dbEngine{
		name:              "snowflake",
		defaultPluginName: "snowflake" + dbPluginSuffix,
	}
	dbEngineRedis = &dbEngine{
		name:              "redis",
		defaultPluginName: "redis" + dbPluginSuffix,
	}
	dbEngineRedisElastiCache = &dbEngine{
		name:              "redis_elasticache",
		defaultPluginName: "redis-elasticache" + dbPluginSuffix,
	}
	dbEngineRedshift = &dbEngine{
		name:              "redshift",
		defaultPluginName: "redshift" + dbPluginSuffix,
	}

	dbEngines = []*dbEngine{
		dbEngineCassandra,
		dbEngineCouchbase,
		dbEngineElasticSearch,
		dbEngineHana,
		dbEngineInfluxDB,
		dbEngineMSSQL,
		dbEngineMongoDB,
		dbEngineMongoDBAtlas,
		dbEngineMySQL,
		dbEngineMySQLAurora,
		dbEngineMySQLLegacy,
		dbEngineMySQLRDS,
		dbEnginePostgres,
		dbEngineOracle,
		dbEngineSnowflake,
		dbEngineRedis,
		dbEngineRedisElastiCache,
		dbEngineRedshift,
	}
)

type dbEngine struct {
	name              string
	defaultPluginName string
	pluginAliases     []string
}

// GetPluginName from the schema.ResourceData if it is configured,
// otherwise return the default plugin name.
// Return an error if no plugin name can be found.
func (i *dbEngine) GetPluginName(d *schema.ResourceData, prefix string) (string, error) {
	if val, ok := d.GetOk(prefix + "plugin_name"); ok {
		return val.(string), nil
	}

	if i.defaultPluginName == "" {
		return "", errors.New("default plugin name not set")
	}

	return i.defaultPluginName, nil
}

func (i *dbEngine) String() string {
	return i.name
}

// Name of the Vault DB secrets engine.
func (i *dbEngine) Name() string {
	return i.name
}

func (i *dbEngine) ResourcePrefix(idx int) string {
	return fmt.Sprintf("%s.%d.", i.name, idx)
}

// DefaultPluginName for this dbEngine.
func (i *dbEngine) DefaultPluginName() string {
	return i.defaultPluginName
}

// PluginPrefix for this dbEngine. Return an error if the prefix is empty.
func (i *dbEngine) PluginPrefix() (string, error) {
	prefix := strings.TrimSuffix(i.DefaultPluginName(), dbPluginSuffix)
	if prefix == "" {
		return "", fmt.Errorf("empty plugin prefix, no default plugin name set for dbEngine %q", i.name)
	}

	return prefix, nil
}

// PluginPrefixes returns a slice of "plugin-name" prefixes that this engine is
// compatible with.
func (i *dbEngine) PluginPrefixes() ([]string, error) {
	defaultPrefix, err := i.PluginPrefix()
	if err != nil {
		return nil, err
	}

	return append([]string{defaultPrefix}, i.pluginAliases...), nil
}

// getDatabaseSchema returns the database-specific schema
func getDatabaseSchema(typ schema.ValueType) schemaMap {
	var dbEngineTypes []string
	for _, e := range dbEngines {
		dbEngineTypes = append(dbEngineTypes, e.name)
	}

	dbSchemaMap := map[string]*schema.Schema{
		dbEngineElasticSearch.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the elasticsearch-database-plugin.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"url": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "The URL for Elasticsearch's API",
					},
					"username": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "The username to be used in the connection URL",
					},
					"password": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "The password to be used in the connection URL",
						Sensitive:   true,
					},
					"ca_cert": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "The path to a PEM-encoded CA cert file to use to verify the Elasticsearch server's identity",
					},
					"ca_path": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "The path to a directory of PEM-encoded CA cert files to use to verify the Elasticsearch server's identity",
					},
					"client_cert": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "The path to the certificate for the Elasticsearch client to present for communication",
					},
					"client_key": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "The path to the key for the Elasticsearch client to use for communication",
					},
					"tls_server_name": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "This, if set, is used to set the SNI host when connecting via TLS",
					},
					"insecure": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     false,
						Description: "Whether to disable certificate verification",
					},
					"username_template": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Template describing how dynamic usernames are generated.",
					},
				},
			},
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineElasticSearch.Name(), dbEngineTypes),
		},
		dbEngineCassandra.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the cassandra-database-plugin plugin.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"hosts": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
						Optional:    true,
						Description: "Cassandra hosts to connect to.",
					},
					"port": {
						Type:         schema.TypeInt,
						Optional:     true,
						Description:  "The transport port to use to connect to Cassandra.",
						ValidateFunc: validation.IsPortNumber,
						Default:      9042,
					},
					"username": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "The username to use when authenticating with Cassandra.",
					},
					"password": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "The password to use when authenticating with Cassandra.",
						Sensitive:   true,
					},
					"tls": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Whether to use TLS when connecting to Cassandra.",
						Default:     true,
					},
					"insecure_tls": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Whether to skip verification of the server certificate when using TLS.",
						Default:     false,
					},
					"pem_bundle": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Concatenated PEM blocks containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate.",
						Sensitive:   true,
					},
					"pem_json": {
						Type:         schema.TypeString,
						Optional:     true,
						Description:  "Specifies JSON containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate.",
						Sensitive:    true,
						ValidateFunc: validation.StringIsJSON,
					},
					"protocol_version": {
						Type:        schema.TypeInt,
						Optional:    true,
						Default:     2,
						Description: "The CQL protocol version to use.",
					},
					"connect_timeout": {
						Type:        schema.TypeInt,
						Optional:    true,
						Default:     5,
						Description: "The number of seconds to use as a connection timeout.",
					},
					"skip_verification": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     false,
						Description: "Skip permissions checks when a connection to Cassandra is first created. These checks ensure that Vault is able to create roles, but can be resource intensive in clusters with many roles.",
					},
				},
			},
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineCassandra.Name(), dbEngineTypes),
		},
		dbEngineCouchbase.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the couchbase-database-plugin plugin.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"hosts": {
						Type: schema.TypeList,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
						Required:    true,
						Description: "A set of Couchbase URIs to connect to. Must use `couchbases://` scheme if `tls` is `true`.",
					},
					"username": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Specifies the username for Vault to use.",
					},
					"password": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Specifies the password corresponding to the given username.",
						Sensitive:   true,
					},
					"tls": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Specifies whether to use TLS when connecting to Couchbase.",
						Default:     false,
					},
					"insecure_tls": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: " Specifies whether to skip verification of the server certificate when using TLS.",
						Default:     false,
					},
					"base64_pem": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Required if `tls` is `true`. Specifies the certificate authority of the Couchbase server, as a PEM certificate that has been base64 encoded.",
						Sensitive:   true,
					},
					"bucket_name": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Required for Couchbase versions prior to 6.5.0. This is only used to verify vault's connection to the server.",
					},
					"username_template": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Template describing how dynamic usernames are generated.",
					},
				},
			},
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineCouchbase.Name(), dbEngineTypes),
		},
		dbEngineInfluxDB.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the influxdb-database-plugin plugin.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"host": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Influxdb host to connect to.",
					},
					"port": {
						Type:         schema.TypeInt,
						Optional:     true,
						Description:  "The transport port to use to connect to Influxdb.",
						Default:      8086,
						ValidateFunc: validation.IsPortNumber,
					},
					"username": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Specifies the username to use for superuser access.",
					},
					"password": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Specifies the password corresponding to the given username.",
						Sensitive:   true,
					},
					"tls": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Whether to use TLS when connecting to Influxdb.",
						Default:     true,
					},
					"insecure_tls": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Whether to skip verification of the server certificate when using TLS.",
						Default:     false,
					},
					"pem_bundle": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Concatenated PEM blocks containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate.",
						Sensitive:   true,
					},
					"pem_json": {
						Type:         schema.TypeString,
						Optional:     true,
						Description:  "Specifies JSON containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate.",
						Sensitive:    true,
						ValidateFunc: validation.StringIsJSON,
					},
					"connect_timeout": {
						Type:        schema.TypeInt,
						Optional:    true,
						Default:     5,
						Description: "The number of seconds to use as a connection timeout.",
					},
					"username_template": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Template describing how dynamic usernames are generated.",
					},
				},
			},
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineInfluxDB.Name(), dbEngineTypes),
		},
		dbEngineMongoDB.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the mongodb-database-plugin plugin.",
			Elem: connectionStringResource(&connectionStringConfig{
				includeUserPass: true,
			}),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineMongoDB.Name(), dbEngineTypes),
		},
		dbEngineMongoDBAtlas.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the mongodbatlas-database-plugin plugin.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"private_key": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "The Private Programmatic API Key used to connect with MongoDB Atlas API.",
						Sensitive:   true,
					},
					"public_key": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "The Public Programmatic API Key used to authenticate with the MongoDB Atlas API.",
					},
					"project_id": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "The Project ID the Database User should be created within.",
					},
				},
			},
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineMongoDBAtlas.Name(), dbEngineTypes),
		},
		dbEngineHana.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the hana-database-plugin plugin.",
			Elem: connectionStringResource(&connectionStringConfig{
				excludeUsernameTemplate: true,
				includeDisableEscaping:  true,
				includeUserPass:         true,
			}),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineHana.Name(), dbEngineTypes),
		},
		dbEngineMSSQL.name: {
			Type:          typ,
			Optional:      true,
			Description:   "Connection parameters for the mssql-database-plugin plugin.",
			Elem:          mssqlConnectionStringResource(),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineMSSQL.Name(), dbEngineTypes),
		},
		dbEngineMySQL.name: {
			Type:          typ,
			Optional:      true,
			Description:   "Connection parameters for the mysql-database-plugin plugin.",
			Elem:          mysqlConnectionStringResource(),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineMySQL.Name(), dbEngineTypes),
		},
		dbEngineMySQLRDS.name: {
			Type:          typ,
			Optional:      true,
			Description:   "Connection parameters for the mysql-rds-database-plugin plugin.",
			Elem:          mysqlConnectionStringResource(),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineMySQLRDS.Name(), dbEngineTypes),
		},
		dbEngineMySQLAurora.name: {
			Type:          typ,
			Optional:      true,
			Description:   "Connection parameters for the mysql-aurora-database-plugin plugin.",
			Elem:          mysqlConnectionStringResource(),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineMySQLAurora.Name(), dbEngineTypes),
		},
		dbEngineMySQLLegacy.name: {
			Type:          typ,
			Optional:      true,
			Description:   "Connection parameters for the mysql-legacy-database-plugin plugin.",
			Elem:          mysqlConnectionStringResource(),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineMySQLLegacy.Name(), dbEngineTypes),
		},
		dbEnginePostgres.name: {
			Type:          typ,
			Optional:      true,
			Description:   "Connection parameters for the postgresql-database-plugin plugin.",
			Elem:          postgresConnectionStringResource(),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEnginePostgres.Name(), dbEngineTypes),
		},
		dbEngineOracle.name: {
			Type:          typ,
			Optional:      true,
			Description:   "Connection parameters for the oracle-database-plugin plugin.",
			Elem:          oracleConnectionStringResource(),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineOracle.Name(), dbEngineTypes),
		},
		dbEngineRedis.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the redis-database-plugin plugin.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"host": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Specifies the host to connect to",
					},
					"port": {
						Type:         schema.TypeInt,
						Optional:     true,
						Description:  "The transport port to use to connect to Redis.",
						Default:      6379,
						ValidateFunc: validation.IsPortNumber,
					},
					"username": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Specifies the username for Vault to use.",
					},
					"password": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Specifies the password corresponding to the given username.",
						Sensitive:   true,
					},
					"tls": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Specifies whether to use TLS when connecting to Redis.",
						Default:     false,
					},
					"insecure_tls": {
						Type:     schema.TypeBool,
						Optional: true,
						Description: "Specifies whether to skip verification of the server " +
							"certificate when using TLS.",
						Default: false,
					},
					"ca_cert": {
						Type:     schema.TypeString,
						Optional: true,
						Description: "The contents of a PEM-encoded CA cert file " +
							"to use to verify the Redis server's identity.",
						Default: false,
					},
				},
			},
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineRedis.Name(), dbEngineTypes),
		},
		dbEngineRedisElastiCache.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the redis-elasticache-database-plugin plugin.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"url": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "The configuration endpoint for the ElastiCache cluster to connect to.",
					},
					"username": {
						Type:     schema.TypeString,
						Optional: true,
						Description: "The AWS access key id to use to talk to ElastiCache. " +
							"If omitted the credentials chain provider is used instead.",
						Sensitive: true,
					},
					"password": {
						Type:     schema.TypeString,
						Optional: true,
						Description: "The AWS secret key id to use to talk to ElastiCache. " +
							"If omitted the credentials chain provider is used instead.",
						Sensitive: true,
					},
					"region": {
						Type:     schema.TypeString,
						Optional: true,
						Description: "The AWS region where the ElastiCache cluster is hosted. " +
							"If omitted the plugin tries to infer the region from the environment.",
					},
				},
			},
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineRedisElastiCache.Name(), dbEngineTypes),
		},
		dbEngineRedshift.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the redshift-database-plugin plugin.",
			Elem: connectionStringResource(&connectionStringConfig{
				includeUserPass:        true,
				includeDisableEscaping: true,
			}),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineRedshift.Name(), dbEngineTypes),
		},
		dbEngineSnowflake.name: {
			Type:        typ,
			Optional:    true,
			Description: "Connection parameters for the snowflake-database-plugin plugin.",
			Elem: connectionStringResource(&connectionStringConfig{
				includeUserPass: true,
			}),
			MaxItems:      1,
			ConflictsWith: util.CalculateConflictsWith(dbEngineSnowflake.Name(), dbEngineTypes),
		},
	}

	return dbSchemaMap
}

func databaseSecretBackendConnectionResource() *schema.Resource {
	s := setCommonDatabaseSchema(getDatabaseSchema(schema.TypeList))
	s["backend"] = &schema.Schema{
		Type:        schema.TypeString,
		Required:    true,
		Description: "Unique name of the Vault mount to configure.",
		ForceNew:    true,
		// standardise on no beginning or trailing slashes
		StateFunc: func(v interface{}) string {
			return strings.Trim(v.(string), "/")
		},
	}

	return &schema.Resource{
		Create: databaseSecretBackendConnectionCreateOrUpdate,
		Read:   provider.ReadWrapper(databaseSecretBackendConnectionRead),
		Update: databaseSecretBackendConnectionCreateOrUpdate,
		Delete: databaseSecretBackendConnectionDelete,
		Exists: databaseSecretBackendConnectionExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: s,
	}
}

func connectionStringResource(config *connectionStringConfig) *schema.Resource {
	res := &schema.Resource{
		Schema: map[string]*schema.Schema{
			"connection_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Connection string to use to connect to the database.",
			},
			"max_open_connections": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum number of open connections to the database.",
				Default:     2,
			},
			"max_idle_connections": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum number of idle connections to the database.",
			},
			"max_connection_lifetime": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum number of seconds a connection may be reused.",
			},
		},
	}
	if config.includeUserPass {
		res.Schema["username"] = &schema.Schema{
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The root credential username used in the connection URL",
		}
		res.Schema["password"] = &schema.Schema{
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The root credential password used in the connection URL",
			Sensitive:   true,
		}
	}

	if config.isCloud {
		res.Schema["auth_type"] = &schema.Schema{
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Specify alternative authorization type. (Only 'gcp_iam' is valid currently)",
		}
		res.Schema["service_account_json"] = &schema.Schema{
			Type:        schema.TypeString,
			Optional:    true,
			Description: "A JSON encoded credential for use with IAM authorization",
			Sensitive:   true,
		}
	}

	if !config.excludeUsernameTemplate {
		res.Schema["username_template"] = &schema.Schema{
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Username generation template.",
		}
	}

	if config.includeDisableEscaping {
		res.Schema["disable_escaping"] = &schema.Schema{
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Disable special character escaping in username and password",
		}
	}

	if config.isCloud {
		res.Schema["auth_type"] = &schema.Schema{
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Specify alternative authorization type. (Only 'gcp_iam' is valid currently)",
		}
		res.Schema["service_account_json"] = &schema.Schema{
			Type:        schema.TypeString,
			Optional:    true,
			Description: "A JSON encoded credential for use with IAM authorization",
			Sensitive:   true,
		}
	}

	return res
}

func postgresConnectionStringResource() *schema.Resource {
	r := connectionStringResource(&connectionStringConfig{
		includeUserPass:        true,
		includeDisableEscaping: true,
		isCloud:                true,
	})
	r.Schema["tls_ca"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    true,
		Description: "The x509 CA file for validating the certificate presented by the PostgreSQL server. Must be PEM encoded.",
	}
	r.Schema["tls_certificate"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    true,
		Description: "The x509 client certificate for connecting to the database. Must be PEM encoded.",
	}
	r.Schema["private_key"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    true,
		Description: "The secret key used for the x509 client certificate. Must be PEM encoded.",
		Sensitive:   true,
	}

	r.Schema["self_managed"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "If set, allows onboarding static roles with a rootless connection configuration.",
	}
	r.Schema["password_authentication"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    true,
		Default:     "password",
		Description: "When set to `scram-sha-256`, passwords will be hashed by Vault before being sent to PostgreSQL.",
	}

	return r
}

func mysqlConnectionStringResource() *schema.Resource {
	r := connectionStringResource(&connectionStringConfig{
		includeUserPass: true,
		isCloud:         true,
	})
	r.Schema["tls_certificate_key"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    true,
		Description: "x509 certificate for connecting to the database. This must be a PEM encoded version of the private key and the certificate combined.",
		Sensitive:   true,
	}
	r.Schema["tls_ca"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    true,
		Description: "x509 CA file for validating the certificate presented by the MySQL server. Must be PEM encoded.",
	}
	return r
}

func mssqlConnectionStringResource() *schema.Resource {
	r := connectionStringResource(&connectionStringConfig{
		includeUserPass:        true,
		includeDisableEscaping: true,
	})
	r.Schema["contained_db"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "Set to true when the target is a Contained Database, e.g. AzureSQL.",
	}

	return r
}

func oracleConnectionStringResource() *schema.Resource {
	r := connectionStringResource(&connectionStringConfig{
		includeUserPass: true,
	})
	r.Schema["split_statements"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "Set to true in order to split statements after semi-colons.",
		Default:     true,
	}
	r.Schema["disconnect_sessions"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "Set to true to disconnect any open sessions prior to running the revocation statements.",
		Default:     true,
	}

	return r
}

func getDBEngine(d *schema.ResourceData) (*dbEngine, error) {
	for _, e := range dbEngines {
		if i, ok := d.GetOk(e.name); ok && len(i.([]interface{})) > 0 {
			return e, nil
		}
	}

	return nil, fmt.Errorf("no supported database engines configured")
}

func getDBEngineFromResp(engines []*dbEngine, r *api.Secret) (*dbEngine, error) {
	pluginName, ok := r.Data["plugin_name"]
	if !ok {
		return nil, fmt.Errorf(`invalid response data, missing "plugin_name"`)
	}

	if pluginName == "" {
		return nil, fmt.Errorf(`invalid response data, "plugin_name" is empty`)
	}

	var last int
	var engine *dbEngine
	for _, e := range engines {
		prefixes, err := e.PluginPrefixes()
		if err != nil {
			return nil, err
		}

		for _, prefix := range prefixes {
			if prefix != "" && strings.HasPrefix(pluginName.(string), prefix) {
				l := len(prefix)
				if last == 0 {
					last = l
				}

				if l >= last {
					engine = e
				}
				last = l
			}
		}
	}

	if engine != nil {
		return engine, nil
	}

	return nil, fmt.Errorf("no supported database engines found for plugin %q", pluginName)
}

func getDatabaseAPIDataForEngine(engine *dbEngine, idx int, d *schema.ResourceData, meta interface{}) (map[string]interface{}, error) {
	prefix := engine.ResourcePrefix(idx)
	data := map[string]interface{}{}

	pluginName, err := engine.GetPluginName(d, prefix)
	if err != nil {
		return nil, err
	}

	data["plugin_name"] = pluginName

	switch engine {
	case dbEngineCassandra:
		setCassandraDatabaseConnectionData(d, prefix, data)
	case dbEngineCouchbase:
		setCouchbaseDatabaseConnectionData(d, prefix, data)
	case dbEngineInfluxDB:
		setInfluxDBDatabaseConnectionData(d, prefix, data)
	case dbEngineHana:
		setDatabaseConnectionDataWithDisableEscaping(d, prefix, data)
	case dbEngineMongoDB:
		setDatabaseConnectionDataWithUserPass(d, prefix, data)
	case dbEngineMongoDBAtlas:
		setMongoDBAtlasDatabaseConnectionData(d, prefix, data)
	case dbEngineMSSQL:
		setMSSQLDatabaseConnectionData(d, prefix, data)
	case dbEngineMySQL:
		setMySQLDatabaseConnectionData(d, prefix, data, meta)
	case dbEngineMySQLRDS:
		setMySQLDatabaseConnectionData(d, prefix, data, meta)
	case dbEngineMySQLAurora:
		setMySQLDatabaseConnectionData(d, prefix, data, meta)
	case dbEngineMySQLLegacy:
		setMySQLDatabaseConnectionData(d, prefix, data, meta)
	case dbEngineOracle:
		setOracleDatabaseConnectionData(d, prefix, data)
	case dbEnginePostgres:
		setPostgresDatabaseConnectionData(d, prefix, data, meta)
	case dbEngineElasticSearch:
		setElasticsearchDatabaseConnectionData(d, prefix, data)
	case dbEngineRedis:
		setRedisDatabaseConnectionData(d, prefix, data)
	case dbEngineRedisElastiCache:
		setRedisElastiCacheDatabaseConnectionData(d, prefix, data)
	case dbEngineSnowflake:
		setDatabaseConnectionDataWithUserPass(d, prefix, data)
	case dbEngineRedshift:
		setDatabaseConnectionDataWithDisableEscaping(d, prefix, data)
	default:
		return nil, fmt.Errorf("unrecognized DB engine: %v", engine)
	}

	return data, nil
}

func setMongoDBAtlasDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOk(prefix + "public_key"); ok {
		data["public_key"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "private_key"); ok {
		data["private_key"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "project_id"); ok {
		data["project_id"] = v.(string)
	}
}

func setCassandraDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOk(prefix + "hosts"); ok {
		log.Printf("[DEBUG] Cassandra hosts: %v", v.([]interface{}))
		var hosts []string
		for _, host := range v.([]interface{}) {
			if v == nil {
				continue
			}
			hosts = append(hosts, host.(string))
		}
		data["hosts"] = strings.Join(hosts, ",")
	}
	if v, ok := d.GetOkExists(prefix + "port"); ok {
		data["port"] = v.(int)
	}
	if v, ok := d.GetOk(prefix + "username"); ok {
		data["username"] = v.(string)
	}

	passwordKey := prefix + consts.FieldPassword
	if v, ok := d.GetOk(passwordKey); ok {
		if d.IsNewResource() || d.HasChange(passwordKey) {
			data[consts.FieldPassword] = v.(string)
		}
	}

	if v, ok := d.GetOkExists(prefix + "tls"); ok {
		data["tls"] = v.(bool)
	}
	if v, ok := d.GetOkExists("cassandra.0.insecure_tls"); ok {
		data["insecure_tls"] = v.(bool)
	}
	if v, ok := d.GetOkExists("cassandra.0.pem_bundle"); ok {
		data["pem_bundle"] = v.(string)
	}
	if v, ok := d.GetOkExists(prefix + "pem_json"); ok {
		data["pem_json"] = v.(string)
	}
	if v, ok := d.GetOkExists(prefix + "protocol_version"); ok {
		data["protocol_version"] = v.(int)
	}
	if v, ok := d.GetOkExists(prefix + "connect_timeout"); ok {
		data["connect_timeout"] = v.(int)
	}
	if v, ok := d.GetOkExists(prefix + "skip_verification"); ok {
		data["skip_verification"] = v.(bool)
	}
}

func getConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := map[string]interface{}{}
	if v, ok := d.GetOk(prefix + "connection_url"); ok {
		result["connection_url"] = v.(string)
	} else {
		if v, ok := data["connection_url"]; ok {
			result["connection_url"] = v.(string)
		}
	}
	if v, ok := data["max_open_connections"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			log.Printf("[WARN] Non-number %s returned from Vault server: %s", v, err)
		} else {
			result["max_open_connections"] = n
		}
	}
	if v, ok := data["max_idle_connections"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			log.Printf("[WARN] Non-number %s returned from Vault server: %s", v, err)
		} else {
			result["max_idle_connections"] = n
		}
	}
	if v, ok := data["max_connection_lifetime"]; ok {
		n, err := time.ParseDuration(v.(string))
		if err != nil {
			log.Printf("[WARN] Non-number %s returned from Vault server: %s", v, err)
		} else {
			result["max_connection_lifetime"] = n.Seconds()
		}
	}
	if _, ok := d.GetOk(prefix + "username_template"); ok {
		if v, ok := data["username_template"]; ok {
			result["username_template"] = v.(string)
		}
	} else {
		if v, ok := data["username_template"]; ok {
			result["username_template"] = v.(string)
		}
	}

	return result
}

func getMSSQLConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) (map[string]interface{}, error) {
	result := getConnectionDetailsFromResponseWithDisableEscaping(d, prefix, resp)
	if result == nil {
		return nil, nil
	}

	details := resp.Data["connection_details"].(map[string]interface{})
	if v, ok := details["contained_db"]; ok {
		containedDB, err := parseutil.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf(`unsupported type for field "contained_db, err=%w"`, err)
		}
		result["contained_db"] = containedDB
	}

	return result, nil
}

func getPostgresConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret, meta interface{}) map[string]interface{} {
	result := getConnectionDetailsFromResponseWithDisableEscaping(d, prefix, resp)
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}

	// cloud specific
	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		if v, ok := data["auth_type"]; ok {
			result["auth_type"] = v.(string)
		}
		if v, ok := d.GetOk(prefix + "service_account_json"); ok {
			result["service_account_json"] = v.(string)
		} else {
			if v, ok := data["service_account_json"]; ok {
				result["service_account_json"] = v.(string)
			}
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion114) {
		if v, ok := data["password_authentication"]; ok {
			result["password_authentication"] = v.(string)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion118) {
		if v, ok := data["tls_ca"]; ok {
			result["tls_ca"] = v.(string)
		}
		if v, ok := data["tls_certificate"]; ok {
			result["tls_certificate"] = v.(string)
		}
		// the private key is a secret that is never revealed by Vault
		result["private_key"] = d.Get(prefix + "private_key")
	}

	if provider.IsAPISupported(meta, provider.VaultVersion118) && provider.IsEnterpriseSupported(meta) {
		if v, ok := data["self_managed"]; ok {
			result["self_managed"] = v.(bool)
		}
	}
	return result
}

func getConnectionDetailsFromResponseWithDisableEscaping(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	result := getConnectionDetailsFromResponseWithUserPass(d, prefix, resp)
	if result == nil {
		return nil
	}

	details := resp.Data["connection_details"].(map[string]interface{})
	if v, ok := details["disable_escaping"]; ok {
		result["disable_escaping"] = v.(bool)
	}

	return result
}

func getMySQLConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret, meta interface{}) map[string]interface{} {
	result := getConnectionDetailsFromResponseWithUserPass(d, prefix, resp)
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	if v, ok := d.GetOk(prefix + "tls_certificate_key"); ok {
		result["tls_certificate_key"] = v.(string)
	} else {
		if v, ok := data["tls_certificate_key"]; ok {
			result["tls_certificate_key"] = v.(string)
		}
	}
	if v, ok := d.GetOk(prefix + "tls_ca"); ok {
		result["tls_ca"] = v.(string)
	} else {
		if v, ok := data["tls_ca"]; ok {
			result["tls_ca"] = v.(string)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion115) {
		// cloud specific
		if v, ok := data["auth_type"]; ok {
			result["auth_type"] = v.(string)
		}
		if v, ok := d.GetOk(prefix + "service_account_json"); ok {
			result["service_account_json"] = v.(string)
		} else {
			if v, ok := data["service_account_json"]; ok {
				result["service_account_json"] = v.(string)
			}
		}
	}

	return result
}

func getRedisConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := map[string]interface{}{}

	if v, ok := data["host"]; ok {
		result["host"] = v.(string)
	}
	if v, ok := data["port"]; ok {
		port, _ := v.(json.Number).Int64()
		result["port"] = port
	}
	if v, ok := data["username"]; ok {
		result["username"] = v.(string)
	}
	if v, ok := data["password"]; ok {
		result["password"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "password"); ok {
		// keep the password we have in state/config if the API doesn't return one
		result["password"] = v.(string)
	}
	if v, ok := data["tls"]; ok {
		result["tls"] = v.(bool)
	}
	if v, ok := data["insecure_tls"]; ok {
		result["insecure_tls"] = v.(bool)
	}
	if v, ok := data["ca_cert"]; ok {
		result["ca_cert"] = v.(string)
	}

	return result
}

func getRedisElastiCacheConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}

	result := map[string]interface{}{}
	if v, ok := data["url"]; ok {
		result["url"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "url"); ok {
		result["url"] = v.(string)
	}
	if v, ok := data["username"]; ok {
		result["username"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "username"); ok {
		result["username"] = v.(string)
	}
	if v, ok := data["password"]; ok {
		result["password"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "password"); ok {
		result["password"] = v.(string)
	}
	if v, ok := data["region"]; ok {
		result["region"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "region"); ok {
		result["region"] = v.(string)
	}

	return result
}

func getElasticsearchConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := map[string]interface{}{}
	if v, ok := d.GetOk(prefix + "url"); ok {
		result["url"] = v.(string)
	} else {
		if v, ok := data["url"]; ok {
			result["url"] = v.(string)
		}
	}

	if v, ok := data["username"]; ok {
		result["username"] = v.(string)
	}
	if v, ok := data["password"]; ok {
		result["password"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "password"); ok {
		// keep the password we have in state/config if the API doesn't return one
		result["password"] = v.(string)
	}
	if v, ok := data["ca_cert"]; ok {
		result["ca_cert"] = v.(string)
	}
	if v, ok := data["ca_path"]; ok {
		result["ca_path"] = v.(string)
	}
	if v, ok := data["client_cert"]; ok {
		result["client_cert"] = v.(string)
	}
	if v, ok := data["client_key"]; ok {
		result["client_key"] = v.(string)
	}
	if v, ok := data["tls_server_name"]; ok {
		result["tls_server_name"] = v.(string)
	}
	if v, ok := data["insecure"]; ok {
		result["insecure"] = v.(bool)
	}
	if v, ok := data["username_template"]; ok {
		result["username_template"] = v.(string)
	}

	return result
}

func getCouchbaseConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := map[string]interface{}{}

	if v, ok := data["hosts"]; ok {
		result["hosts"] = strings.Split(v.(string), ",")
	}
	if v, ok := data["username"]; ok {
		result["username"] = v.(string)
	}
	if v, ok := data["password"]; ok {
		result["password"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "password"); ok {
		// keep the password we have in state/config if the API doesn't return one
		result["password"] = v.(string)
	}
	if v, ok := data["tls"]; ok {
		result["tls"] = v.(bool)
	}
	if v, ok := data["insecure_tls"]; ok {
		result["insecure_tls"] = v.(bool)
	}

	// base64_pem maps to base64pem in Vault
	result["base64_pem"] = data["base64pem"]

	if v, ok := data["bucket_name"]; ok {
		result["bucket_name"] = v.(string)
	}
	if v, ok := data["username_template"]; ok {
		result["username_template"] = v.(string)
	}

	return result
}

func getInfluxDBConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := map[string]interface{}{}

	if v, ok := data["host"]; ok {
		result["host"] = v.(string)
	}
	if v, ok := data["port"]; ok {
		port, _ := v.(json.Number).Int64()
		result["port"] = port
	}
	if v, ok := data["username"]; ok {
		result["username"] = v.(string)
	}
	if v, ok := data["password"]; ok {
		result["password"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "password"); ok {
		// keep the password we have in state/config if the API doesn't return one
		result["password"] = v.(string)
	}
	if v, ok := data["tls"]; ok {
		result["tls"] = v.(bool)
	}
	if v, ok := data["insecure_tls"]; ok {
		result["insecure_tls"] = v.(bool)
	}
	if v, ok := data["pem_bundle"]; ok {
		result["pem_bundle"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "pem_bundle"); ok {
		result["pem_bundle"] = v.(string)
	}
	if v, ok := data["pem_json"]; ok {
		result["pem_json"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "pem_json"); ok {
		result["pem_json"] = v.(string)
	}
	if v, ok := data["protocol_version"]; ok {
		protocol, _ := v.(json.Number).Int64()
		result["protocol_version"] = int64(protocol)
	}
	if v, ok := data["connect_timeout"]; ok {
		timeout, _ := v.(json.Number).Int64()
		result["connect_timeout"] = timeout
	}
	if v, ok := data["username_template"]; ok {
		result["username_template"] = v.(string)
	}

	return result
}

func getSnowflakeConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}

	result := getConnectionDetailsFromResponseWithUserPass(d, prefix, resp)
	if v, ok := data["username"]; ok {
		result["username"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "password"); ok {
		result["password"] = v.(string)
	} else {
		if v, ok := data["password"]; ok {
			result["password"] = v.(string)
		}
	}

	if v, ok := d.GetOk(prefix + "username_template"); ok {
		result["username_template"] = v.(string)
	} else {
		if v, ok := data["username_template"]; ok {
			result["username_template"] = v.(string)
		}
	}

	return result
}

func getConnectionDetailsFromResponseWithUserPass(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	result := getConnectionDetailsFromResponse(d, prefix, resp)
	if result == nil {
		return nil
	}

	details := resp.Data["connection_details"].(map[string]interface{})
	if v, ok := details["username"]; ok {
		result["username"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "password"); ok {
		result["password"] = v.(string)
	}

	return result
}

func getOracleConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}

	result := getConnectionDetailsFromResponseWithUserPass(d, prefix, resp)
	if v, ok := data["split_statements"]; ok {
		result["split_statements"] = v.(bool)
	}

	if v, ok := data["disconnect_sessions"]; ok {
		result["disconnect_sessions"] = v.(bool)
	}

	return result
}

func setDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOk(prefix + "connection_url"); ok {
		data["connection_url"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "max_open_connections"); ok {
		data["max_open_connections"] = v.(int)
	}
	if v, ok := d.GetOkExists(prefix + "max_idle_connections"); ok {
		data["max_idle_connections"] = v.(int)
	}
	if v, ok := d.GetOkExists(prefix + "max_connection_lifetime"); ok {
		data["max_connection_lifetime"] = fmt.Sprintf("%ds", v)
	}
	if v, ok := d.GetOkExists(prefix + "username_template"); ok {
		data["username_template"] = v.(string)
	}
}

func setCloudDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}, meta interface{}) {
	if !provider.IsAPISupported(meta, provider.VaultVersion115) {
		return
	}
	if v, ok := d.GetOk(prefix + "auth_type"); ok {
		data["auth_type"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "service_account_json"); ok {
		data["service_account_json"] = v.(string)
	}
}

func setMSSQLDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	setDatabaseConnectionDataWithDisableEscaping(d, prefix, data)
	if v, ok := d.GetOk(prefix + "contained_db"); ok {
		// TODO:
		//  we have to pass string value here due to an issue with the
		//  way the mssql plugin handles this field. We can probably revert this once vault-1.9.3
		//  is released.
		data["contained_db"] = strconv.FormatBool(v.(bool))
	}
}

func setMySQLDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}, meta interface{}) {
	setDatabaseConnectionDataWithUserPass(d, prefix, data)
	setCloudDatabaseConnectionData(d, prefix, data, meta)
	if v, ok := d.GetOk(prefix + "tls_certificate_key"); ok {
		data["tls_certificate_key"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "tls_ca"); ok {
		data["tls_ca"] = v.(string)
	}
}

func setPostgresDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}, meta interface{}) {
	setDatabaseConnectionDataWithDisableEscaping(d, prefix, data)
	setCloudDatabaseConnectionData(d, prefix, data, meta)

	if provider.IsAPISupported(meta, provider.VaultVersion118) {
		if v, ok := d.GetOk(prefix + "tls_ca"); ok {
			data["tls_ca"] = v.(string)
		}
		if v, ok := d.GetOk(prefix + "tls_certificate"); ok {
			data["tls_certificate"] = v.(string)
		}
		if v, ok := d.GetOk(prefix + "private_key"); ok {
			data["private_key"] = v.(string)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion114) {
		if v, ok := d.GetOk(prefix + "password_authentication"); ok {
			data["password_authentication"] = v.(string)
		}
	}

	if provider.IsAPISupported(meta, provider.VaultVersion118) && provider.IsEnterpriseSupported(meta) {
		if v, ok := d.GetOk(prefix + "self_managed"); ok {
			data["self_managed"] = v.(bool)
		}
	}
}

func setRedisDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOk(prefix + "host"); ok {
		data["host"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "port"); ok {
		data["port"] = v.(int)
	}
	if v, ok := d.GetOk(prefix + "username"); ok {
		data["username"] = v.(string)
	}

	passwordKey := prefix + consts.FieldPassword
	if v, ok := d.GetOk(passwordKey); ok {
		if d.IsNewResource() || d.HasChange(passwordKey) {
			data[consts.FieldPassword] = v.(string)
		}
	}

	if v, ok := d.GetOk(prefix + "tls"); ok {
		data["tls"] = v.(bool)
	}
	if v, ok := d.GetOk(prefix + "insecure_tls"); ok {
		data["insecure_tls"] = v.(bool)
	}
	if v, ok := d.GetOk(prefix + "ca_cert"); ok {
		data["ca_cert"] = v.(string)
	}
}

func setRedisElastiCacheDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOk(prefix + "url"); ok {
		data["url"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "username"); ok {
		data["username"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "password"); ok {
		data["password"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "region"); ok {
		data["region"] = v.(string)
	}
}

func setElasticsearchDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOk(prefix + "url"); ok {
		data["url"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "username"); ok {
		data["username"] = v.(string)
	}

	passwordKey := prefix + consts.FieldPassword
	if v, ok := d.GetOk(passwordKey); ok {
		if d.IsNewResource() || d.HasChange(passwordKey) {
			data[consts.FieldPassword] = v.(string)
		}
	}

	if v, ok := d.GetOk(prefix + "ca_cert"); ok {
		data["ca_cert"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "ca_path"); ok {
		data["ca_path"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "client_cert"); ok {
		data["client_cert"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "client_key"); ok {
		data["client_key"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "tls_server_name"); ok {
		data["tls_server_name"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "insecure"); ok {
		data["insecure"] = v.(bool)
	}

	if v, ok := d.GetOk(prefix + "username_template"); ok {
		data["username_template"] = v.(string)
	}
}

func setCouchbaseDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOkExists(prefix + "hosts"); ok && v != nil {
		var hosts []string
		for _, host := range v.([]interface{}) {
			hosts = append(hosts, host.(string))
		}
		data["hosts"] = strings.Join(hosts, ",")
	}
	if v, ok := d.GetOk(prefix + "username"); ok {
		data["username"] = v
	}

	passwordKey := prefix + consts.FieldPassword
	if v, ok := d.GetOk(passwordKey); ok {
		if d.IsNewResource() || d.HasChange(passwordKey) {
			data[consts.FieldPassword] = v.(string)
		}
	}

	if v, ok := d.GetOkExists(prefix + "tls"); ok {
		data["tls"] = v.(bool)
	}
	if v, ok := d.GetOkExists(prefix + "insecure_tls"); ok {
		data["insecure_tls"] = v.(bool)
	}
	if v, ok := d.GetOk(prefix + "base64_pem"); ok {
		// base64_pem maps to base64pem in Vault
		data["base64pem"] = v
	}
	if v, ok := d.GetOk(prefix + "bucket_name"); ok {
		data["bucket_name"] = v
	}
	if v, ok := d.GetOk(prefix + "username_template"); ok {
		data["username_template"] = v
	}
}

func setInfluxDBDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOkExists(prefix + "host"); ok {
		data["host"] = v.(string)
	}
	if v, ok := d.GetOkExists(prefix + "port"); ok {
		data["port"] = v.(int)
	}
	if v, ok := d.GetOk(prefix + "username"); ok {
		data["username"] = v.(string)
	}

	passwordKey := prefix + consts.FieldPassword
	if v, ok := d.GetOk(passwordKey); ok {
		if d.IsNewResource() || d.HasChange(passwordKey) {
			data[consts.FieldPassword] = v.(string)
		}
	}

	if v, ok := d.GetOkExists(prefix + "tls"); ok {
		data["tls"] = v.(bool)
	}
	if v, ok := d.GetOkExists(prefix + "insecure_tls"); ok {
		data["insecure_tls"] = v.(bool)
	}
	if v, ok := d.GetOkExists(prefix + "pem_bundle"); ok {
		data["pem_bundle"] = v.(string)
	}
	if v, ok := d.GetOkExists(prefix + "pem_json"); ok {
		data["pem_json"] = v.(string)
	}
	if v, ok := d.GetOkExists(prefix + "connect_timeout"); ok {
		data["connect_timeout"] = v.(int)
	}
	if v, ok := d.GetOkExists(prefix + "username_template"); ok {
		data["username_template"] = v.(int)
	}
}

func setOracleDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	setDatabaseConnectionDataWithUserPass(d, prefix, data)
	if v, ok := d.GetOkExists(prefix + "split_statements"); ok {
		data["split_statements"] = v.(bool)
	}
	if v, ok := d.GetOkExists(prefix + "disconnect_sessions"); ok {
		data["disconnect_sessions"] = v.(bool)
	}
}

func setDatabaseConnectionDataWithUserPass(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	setDatabaseConnectionData(d, prefix, data)

	data["username"] = d.Get(prefix + "username")

	// Vault does not return the password in the API. If the root credentials have been rotated, sending
	// the old password in the update request would break the connection config. Thus we only send it,
	// if it actually changed to still support updating it for non-rotated cases.
	passwordKey := prefix + consts.FieldPassword
	if v, ok := d.GetOk(passwordKey); ok {
		if d.IsNewResource() || d.HasChange(passwordKey) {
			data[consts.FieldPassword] = v.(string)
		}
	}
}

func setDatabaseConnectionDataWithDisableEscaping(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	setDatabaseConnectionDataWithUserPass(d, prefix, data)

	data["disable_escaping"] = d.Get(prefix + "disable_escaping")
}

func databaseSecretBackendConnectionCreateOrUpdate(
	d *schema.ResourceData, meta interface{},
) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	engine, err := getDBEngine(d)
	if err != nil {
		return err
	}

	path := databaseSecretBackendConnectionPath(
		d.Get("backend").(string), d.Get("name").(string))
	if err := writeDatabaseSecretConfig(
		d, client, engine, 0, false, path, meta); err != nil {
		return err
	}

	d.SetId(path)
	log.Printf("[DEBUG] Wrote database connection config %q", path)

	return databaseSecretBackendConnectionRead(d, meta)
}

func writeDatabaseSecretConfig(d *schema.ResourceData, client *api.Client,
	engine *dbEngine, idx int, unifiedSchema bool, path string, meta interface{},
) error {
	data, err := getDatabaseAPIDataForEngine(engine, idx, d, meta)
	if err != nil {
		return err
	}

	var prefix string
	// unifiedSchema alters the resource key prefix so that the all values
	// are accessed from the engine schema level, rather than from the top level.
	if unifiedSchema {
		prefix = engine.ResourcePrefix(idx)
	}

	if v, ok := d.GetOkExists(prefix + "verify_connection"); ok {
		data["verify_connection"] = v.(bool)
	}

	if v, ok := d.GetOkExists(prefix + "allowed_roles"); ok {
		var roles []string
		for _, role := range v.([]interface{}) {
			roles = append(roles, role.(string))
		}
		data["allowed_roles"] = strings.Join(roles, ",")
	}

	if v, ok := d.GetOk("root_rotation_statements"); ok {
		data["root_rotation_statements"] = v
	}

	if m, ok := d.GetOkExists(prefix + "data"); ok {
		for k, v := range m.(map[string]interface{}) {
			// Vault does not return the password in the API. If the root credentials have been rotated, sending
			// the old password in the update request would break the connection config. Thus we only send it,
			// if it actually changed, to still support updating it for non-rotated cases.
			if k == "password" && (d.IsNewResource() || (d.HasChange(k) && !d.IsNewResource())) {
				data[k] = v.(string)
			}
		}
	}

	log.Printf("[DEBUG] Writing connection config to %q", path)
	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error configuring database connection %q: %s", path, err)
	}

	log.Printf("[DEBUG] Wrote database connection config %q", path)

	return nil
}

func validateDBPluginName(s string) error {
	pluginPrefixes, err := getSortedPluginPrefixes()
	if err != nil {
		return err
	}

	for _, v := range pluginPrefixes {
		if strings.HasPrefix(s, v) {
			return nil
		}
	}

	return fmt.Errorf("unsupported database plugin name %q, must begin with one of: %s", s,
		strings.Join(pluginPrefixes, ", "))
}

func getSortedPluginPrefixes() ([]string, error) {
	var pluginPrefixes []string
	for _, d := range dbEngines {
		prefixes, err := d.PluginPrefixes()
		if err != nil {
			return nil, err
		}
		pluginPrefixes = append(pluginPrefixes, prefixes...)
	}
	// sorted by max length
	sort.Slice(pluginPrefixes, func(i, j int) bool {
		return len(pluginPrefixes[i]) > len(pluginPrefixes[j])
	})

	return pluginPrefixes, nil
}

func databaseSecretBackendConnectionRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	backend, err := databaseSecretBackendConnectionBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for database connection: %s", path, err)
	}

	name, err := databaseSecretBackendConnectionNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for database connection: %s", path, err)
	}

	log.Printf("[DEBUG] Reading database connection config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading database connection config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read database connection config %q", path)
	if resp == nil {
		log.Printf("[WARN] Database connection %q not found, removing it from state", path)
		d.SetId("")
		return nil
	}

	engine, err := getDBEngine(d)
	if err != nil {
		// on resource import we must rely on the `plugin_name` configured in
		// Vault to get the corresponding dbEngine.
		engine, err = getDBEngineFromResp(dbEngines, resp)
	}
	if err != nil {
		return err
	}

	result, err := getDBConnectionConfig(d, engine, 0, resp, meta)
	if err != nil {
		return err
	}

	if err := d.Set(engine.Name(), []map[string]interface{}{result}); err != nil {
		return err
	}

	if err := d.Set("backend", backend); err != nil {
		return err
	}

	for k, v := range getDBCommonConfig(d, resp, engine, 0, false, name) {
		if err := d.Set(k, v); err != nil {
			return err
		}
	}

	return nil
}

func getDBCommonConfig(d *schema.ResourceData, resp *api.Secret,
	engine *dbEngine, idx int, unifiedSchema bool, name string,
) map[string]interface{} {
	var roles []string
	for _, role := range resp.Data["allowed_roles"].([]interface{}) {
		roles = append(roles, role.(string))
	}

	var prefix string
	if unifiedSchema {
		prefix = engine.ResourcePrefix(idx)
	}

	result := map[string]interface{}{
		"name":              name,
		"allowed_roles":     roles,
		"data":              d.Get(prefix + "data"),
		"verify_connection": d.Get(prefix + "verify_connection"),
		"plugin_name":       resp.Data["plugin_name"],
	}

	//"root_rotation_statements": resp.Data["root_credentials_rotate_statements"],
	rootRotationStmts := make([]string, 0)
	if v, ok := resp.Data["root_credentials_rotate_statements"]; ok && v != nil {
		for _, s := range v.([]interface{}) {
			rootRotationStmts = append(rootRotationStmts, s.(string))
		}
	}
	result["root_rotation_statements"] = rootRotationStmts

	return result
}

func getDBConnectionConfig(d *schema.ResourceData, engine *dbEngine, idx int,
	resp *api.Secret, meta interface{},
) (map[string]interface{}, error) {
	var result map[string]interface{}

	prefix := engine.ResourcePrefix(idx)
	switch engine {
	case dbEngineCassandra:
		values, err := getConnectionDetailsCassandra(d, prefix, resp)
		if err != nil {
			return nil, err
		}
		result = values
	case dbEngineCouchbase:
		result = getCouchbaseConnectionDetailsFromResponse(d, prefix, resp)
	case dbEngineInfluxDB:
		result = getInfluxDBConnectionDetailsFromResponse(d, prefix, resp)
	case dbEngineHana:
		result = getConnectionDetailsFromResponseWithDisableEscaping(d, prefix, resp)
	case dbEngineMongoDB:
		result = getConnectionDetailsFromResponseWithUserPass(d, prefix, resp)
	case dbEngineMongoDBAtlas:
		result = getConnectionDetailsMongoDBAtlas(d, prefix, resp)
	case dbEngineMSSQL:
		values, err := getMSSQLConnectionDetailsFromResponse(d, prefix, resp)
		if err != nil {
			return nil, err
		}
		result = values
	case dbEngineMySQL:
		result = getMySQLConnectionDetailsFromResponse(d, prefix, resp, meta)
	case dbEngineMySQLRDS:
		result = getMySQLConnectionDetailsFromResponse(d, prefix, resp, meta)
	case dbEngineMySQLAurora:
		result = getMySQLConnectionDetailsFromResponse(d, prefix, resp, meta)
	case dbEngineMySQLLegacy:
		result = getMySQLConnectionDetailsFromResponse(d, prefix, resp, meta)
	case dbEngineOracle:
		result = getOracleConnectionDetailsFromResponse(d, prefix, resp)
	case dbEnginePostgres:
		result = getPostgresConnectionDetailsFromResponse(d, prefix, resp, meta)
	case dbEngineElasticSearch:
		result = getElasticsearchConnectionDetailsFromResponse(d, prefix, resp)
	case dbEngineSnowflake:
		result = getSnowflakeConnectionDetailsFromResponse(d, prefix, resp)
	case dbEngineRedis:
		result = getRedisConnectionDetailsFromResponse(d, prefix, resp)
	case dbEngineRedisElastiCache:
		result = getRedisElastiCacheConnectionDetailsFromResponse(d, prefix, resp)
	case dbEngineRedshift:
		result = getConnectionDetailsFromResponseWithDisableEscaping(d, prefix, resp)
	default:
		return nil, fmt.Errorf("no response handler for dbEngine: %s", engine)
	}

	return result, nil
}

func getConnectionDetailsCassandra(d *schema.ResourceData, prefix string, resp *api.Secret) (map[string]interface{}, error) {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if ok {
		result := map[string]interface{}{}

		if v, ok := data["hosts"]; ok {
			result["hosts"] = strings.Split(v.(string), ",")
		}
		if v, ok := data["port"]; ok {
			port, err := v.(json.Number).Int64()
			if err != nil {
				return nil, fmt.Errorf("unexpected non-number %q returned as port from Vault: %s", v, err)
			}
			result["port"] = port
		}
		if v, ok := data["username"]; ok {
			result["username"] = v.(string)
		}
		if v, ok := data["password"]; ok {
			result["password"] = v.(string)
		} else if v, ok := d.GetOk(prefix + "password"); ok {
			// keep the password we have in state/config if the API doesn't return one
			result["password"] = v.(string)
		}
		if v, ok := data["tls"]; ok {
			result["tls"] = v.(bool)
		}
		if v, ok := data["insecure_tls"]; ok {
			result["insecure_tls"] = v.(bool)
		}
		if v, ok := data["pem_bundle"]; ok {
			result["pem_bundle"] = v.(string)
		} else if v, ok := d.GetOk(prefix + "pem_bundle"); ok {
			result["pem_bundle"] = v.(string)
		}
		if v, ok := data["pem_json"]; ok {
			result["pem_json"] = v.(string)
		} else if v, ok := d.GetOk(prefix + "pem_json"); ok {
			result["pem_json"] = v.(string)
		}
		if v, ok := data["protocol_version"]; ok {
			protocol, err := v.(json.Number).Int64()
			if err != nil {
				return nil, fmt.Errorf("unexpected non-number %q returned as protocol_version from Vault: %s", v, err)
			}
			result["protocol_version"] = int64(protocol)
		}
		if v, ok := data["connect_timeout"]; ok {
			timeout, err := v.(json.Number).Int64()
			if err != nil {
				return nil, fmt.Errorf("unexpected non-number %q returned as connect_timeout from Vault: %s", v, err)
			}
			result["connect_timeout"] = timeout
		}
		if v, ok := data["skip_verification"]; ok {
			result["skip_verification"] = v.(bool)
		}
		return result, nil
	}
	return nil, nil
}

func getConnectionDetailsMongoDBAtlas(d *schema.ResourceData, prefix string, resp *api.Secret) map[string]interface{} {
	result := map[string]interface{}{
		// the private key is a secret that is never revealed by Vault
		"private_key": d.Get(prefix + "private_key"),
	}
	if details, ok := resp.Data["connection_details"]; ok {
		if data, ok := details.(map[string]interface{}); ok {
			for _, k := range []string{"public_key", "project_id"} {
				result[k] = data[k]
			}
		}
	}

	return result
}

func databaseSecretBackendConnectionDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Removing database connection config %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error removing database connection config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Removed database connection config %q", path)

	return nil
}

func databaseSecretBackendConnectionExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()

	log.Printf("[DEBUG] Checking if database connection config %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of database connection config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if database connection config %q exists", path)
	return resp != nil, nil
}

func databaseSecretBackendConnectionPath(backend, name string) string {
	return strings.Trim(backend, "/") + "/config/" + strings.Trim(name, "/")
}

func databaseSecretBackendConnectionNameFromPath(path string) (string, error) {
	if !databaseSecretBackendConnectionNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := databaseSecretBackendConnectionNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func databaseSecretBackendConnectionBackendFromPath(path string) (string, error) {
	if !databaseSecretBackendConnectionBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := databaseSecretBackendConnectionBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
