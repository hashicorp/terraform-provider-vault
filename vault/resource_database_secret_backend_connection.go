package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/util"
)

type connectionStringConfig struct {
	excludeUsernameTemplate bool
	includeUserPass         bool
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
	}
	dbEngineSnowflake = &dbEngine{
		name:              "snowflake",
		defaultPluginName: "snowflake" + dbPluginSuffix,
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
		dbEngineRedshift,
	}
)

type dbEngine struct {
	name              string
	defaultPluginName string
}

// GetPluginName from the schema.ResourceData if it is configured,
// otherwise return the default plugin name.
// Return an error if no plugin name can be found.
func (i *dbEngine) GetPluginName(d *schema.ResourceData) (string, error) {
	if val, ok := d.GetOk("plugin_name"); ok {
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

// DefaultPluginName for this dbEngine.
func (i *dbEngine) DefaultPluginName() string {
	return i.defaultPluginName
}

func databaseSecretBackendConnectionResource() *schema.Resource {
	dbEngineTypes := []string{}
	for _, e := range dbEngines {
		dbEngineTypes = append(dbEngineTypes, e.name)
	}

	return &schema.Resource{
		Create: databaseSecretBackendConnectionCreate,
		Read:   databaseSecretBackendConnectionRead,
		Update: databaseSecretBackendConnectionUpdate,
		Delete: databaseSecretBackendConnectionDelete,
		Exists: databaseSecretBackendConnectionExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the database connection.",
				ForceNew:    true,
			},
			"plugin_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the name of the plugin to use for this connection.",
			},
			"verify_connection": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Specifies if the connection is verified during initial configuration.",
				Default:     true,
			},
			"allowed_roles": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A list of roles that are allowed to use this connection.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"root_rotation_statements": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A list of database statements to be executed to rotate the root user's credentials.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"data": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "A map of sensitive data to pass to the endpoint. Useful for templated connection strings.",
				Sensitive:   true,
			},

			"elasticsearch": {
				Type:        schema.TypeList,
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
					},
				},
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineElasticSearch.Name(), dbEngineTypes),
			},

			dbEngineCassandra.name: {
				Type:        schema.TypeList,
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
					},
				},
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineCassandra.Name(), dbEngineTypes),
			},

			dbEngineCouchbase.name: {
				Type:        schema.TypeList,
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
				Type:        schema.TypeList,
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
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mongodb-database-plugin plugin.",
				Elem:          connectionStringResource(&connectionStringConfig{}),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineMongoDB.Name(), dbEngineTypes),
			},

			dbEngineMongoDBAtlas.name: {
				Type:        schema.TypeList,
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
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Connection parameters for the hana-database-plugin plugin.",
				Elem: connectionStringResource(&connectionStringConfig{
					excludeUsernameTemplate: true,
				}),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineHana.Name(), dbEngineTypes),
			},

			dbEngineMSSQL.name: {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mssql-database-plugin plugin.",
				Elem:          mssqlConnectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineMSSQL.Name(), dbEngineTypes),
			},

			dbEngineMySQL.name: {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mysql-database-plugin plugin.",
				Elem:          mysqlConnectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineMySQL.Name(), dbEngineTypes),
			},
			dbEngineMySQLRDS.name: {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mysql-rds-database-plugin plugin.",
				Elem:          connectionStringResource(&connectionStringConfig{}),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineMySQLRDS.Name(), dbEngineTypes),
			},
			dbEngineMySQLAurora.name: {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mysql-aurora-database-plugin plugin.",
				Elem:          connectionStringResource(&connectionStringConfig{}),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineMySQLAurora.Name(), dbEngineTypes),
			},
			dbEngineMySQLLegacy.name: {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mysql-legacy-database-plugin plugin.",
				Elem:          connectionStringResource(&connectionStringConfig{}),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineMySQLLegacy.Name(), dbEngineTypes),
			},

			dbEnginePostgres.name: {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the postgresql-database-plugin plugin.",
				Elem:          connectionStringResource(&connectionStringConfig{}),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEnginePostgres.Name(), dbEngineTypes),
			},

			dbEngineOracle.name: {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the oracle-database-plugin plugin.",
				Elem:          connectionStringResource(&connectionStringConfig{}),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineOracle.Name(), dbEngineTypes),
			},

			dbEngineRedshift.name: {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the redshift-database-plugin plugin.",
				Elem:          connectionStringResource(&connectionStringConfig{includeUserPass: true}),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineRedshift.Name(), dbEngineTypes),
			},

			dbEngineSnowflake.name: {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the snowflake-database-plugin plugin.",
				Elem:          connectionStringResource(&connectionStringConfig{includeUserPass: true}),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith(dbEngineSnowflake.Name(), dbEngineTypes),
			},

			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the Vault mount to configure.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
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

	if !config.excludeUsernameTemplate {
		res.Schema["username_template"] = &schema.Schema{
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Username generation template.",
		}
	}

	return res
}

func mysqlConnectionStringResource() *schema.Resource {
	r := connectionStringResource(&connectionStringConfig{})
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
	r := connectionStringResource(&connectionStringConfig{})
	r.Schema["contained_db"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "Set to true when the target is a Contained Database, e.g. AzureSQL.",
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

func getDatabaseAPIData(d *schema.ResourceData) (map[string]interface{}, error) {
	db, err := getDBEngine(d)
	if err != nil {
		return nil, err
	}

	pluginName, err := db.GetPluginName(d)
	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"plugin_name": pluginName,
	}

	switch db {
	case dbEngineCassandra:
		if v, ok := d.GetOk("cassandra.0.hosts"); ok {
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
		if v, ok := d.GetOkExists("cassandra.0.port"); ok {
			data["port"] = v.(int)
		}
		if v, ok := d.GetOk("cassandra.0.username"); ok {
			data["username"] = v.(string)
		}
		if v, ok := d.GetOk("cassandra.0.password"); ok {
			data["password"] = v.(string)
		}
		if v, ok := d.GetOkExists("cassandra.0.tls"); ok {
			data["tls"] = v.(bool)
		}
		if v, ok := d.GetOkExists("cassandra.0.insecure_tls"); ok {
			data["insecure_tls"] = v.(bool)
		}
		if v, ok := d.GetOkExists("cassandra.0.pem_bundle"); ok {
			data["pem_bundle"] = v.(string)
		}
		if v, ok := d.GetOkExists("cassandra.0.pem_json"); ok {
			data["pem_json"] = v.(string)
		}
		if v, ok := d.GetOkExists("cassandra.0.protocol_version"); ok {
			data["protocol_version"] = v.(int)
		}
		if v, ok := d.GetOkExists("cassandra.0.connect_timeout"); ok {
			data["connect_timeout"] = v.(int)
		}
	case dbEngineCouchbase:
		setCouchbaseDatabaseConnectionData(d, "couchbase.0.", data)
	case dbEngineInfluxDB:
		setInfluxDBDatabaseConnectionData(d, "influxdb.0.", data)
	case dbEngineHana:
		setDatabaseConnectionData(d, "hana.0.", data)
	case dbEngineMongoDB:
		setDatabaseConnectionData(d, "mongodb.0.", data)
	case dbEngineMongoDBAtlas:
		if v, ok := d.GetOk("mongodbatlas.0.public_key"); ok {
			data["public_key"] = v.(string)
		}
		if v, ok := d.GetOk("mongodbatlas.0.private_key"); ok {
			data["private_key"] = v.(string)
		}
		if v, ok := d.GetOk("mongodbatlas.0.project_id"); ok {
			data["project_id"] = v.(string)
		}
	case dbEngineMSSQL:
		setMSSQLDatabaseConnectionData(d, "mssql.0.", data)
	case dbEngineMySQL:
		setMySQLDatabaseConnectionData(d, "mysql.0.", data)
	case dbEngineMySQLRDS:
		setDatabaseConnectionData(d, "mysql_rds.0.", data)
	case dbEngineMySQLAurora:
		setDatabaseConnectionData(d, "mysql_aurora.0.", data)
	case dbEngineMySQLLegacy:
		setDatabaseConnectionData(d, "mysql_legacy.0.", data)
	case dbEngineOracle:
		setDatabaseConnectionData(d, "oracle.0.", data)
	case dbEnginePostgres:
		setDatabaseConnectionData(d, "postgresql.0.", data)
	case dbEngineElasticSearch:
		setElasticsearchDatabaseConnectionData(d, "elasticsearch.0.", data)
	case dbEngineSnowflake:
		setDatabaseConnectionDataWithUserPass(d, "snowflake.0.", data)
	case dbEngineRedshift:
		setDatabaseConnectionDataWithUserPass(d, "redshift.0.", data)
	}

	return data, nil
}

func getConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) []map[string]interface{} {
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
	return []map[string]interface{}{result}
}

func getMSSQLConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) ([]map[string]interface{}, error) {
	result := getConnectionDetailsFromResponse(d, prefix, resp)
	if result == nil {
		return nil, nil
	}

	details := resp.Data["connection_details"].(map[string]interface{})
	if v, ok := details["contained_db"]; ok {
		containedDB, err := parseutil.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf(`unsupported type for field "contained_db, err=%w"`, err)
		}
		result[0]["contained_db"] = containedDB
	}
	return result, nil
}

func getMySQLConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) []map[string]interface{} {
	commonDetails := getConnectionDetailsFromResponse(d, prefix, resp)
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := commonDetails[0]
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
	return []map[string]interface{}{result}
}

func getElasticsearchConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) []map[string]interface{} {
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

	return []map[string]interface{}{result}
}

func getCouchbaseConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) []map[string]interface{} {
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
	if v, ok := data["base64_pem"]; ok {
		result["base64_pem"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "base64_pem"); ok {
		result["base64_pem"] = v.(string)
	}
	if v, ok := data["bucket_name"]; ok {
		result["bucket_name"] = v.(string)
	}
	if v, ok := data["username_template"]; ok {
		result["username_template"] = v.(string)
	}

	return []map[string]interface{}{result}
}

func getInfluxDBConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) []map[string]interface{} {
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

	return []map[string]interface{}{result}
}

func getSnowflakeConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) []map[string]interface{} {
	commonDetails := getConnectionDetailsFromResponse(d, prefix, resp)
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := commonDetails[0]

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

	return []map[string]interface{}{result}
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

func setMSSQLDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	setDatabaseConnectionData(d, prefix, data)
	if v, ok := d.GetOk(prefix + "contained_db"); ok {
		// TODO:
		//  we have to pass string value here due to an issue with the
		//  way the mssql plugin handles this field. We can probably revert this once vault-1.9.3
		//  is released.
		data["contained_db"] = strconv.FormatBool(v.(bool))
	}
}

func setMySQLDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	setDatabaseConnectionData(d, prefix, data)
	if v, ok := d.GetOk(prefix + "tls_certificate_key"); ok {
		data["tls_certificate_key"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "tls_ca"); ok {
		data["tls_ca"] = v.(string)
	}
}

func setElasticsearchDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOk(prefix + "url"); ok {
		data["url"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "username"); ok {
		data["username"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "password"); ok {
		data["password"] = v.(string)
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
		data["username"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "password"); ok {
		data["password"] = v.(string)
	}
	if v, ok := d.GetOkExists(prefix + "tls"); ok {
		data["tls"] = v.(bool)
	}
	if v, ok := d.GetOkExists(prefix + "insecure_tls"); ok {
		data["insecure_tls"] = v.(bool)
	}
	if v, ok := d.GetOkExists(prefix + "base64_pem"); ok {
		data["base64_pem"] = v.(string)
	}
	if v, ok := d.GetOkExists(prefix + "bucket_name"); ok {
		data["bucket_name"] = v.(string)
	}
	if v, ok := d.GetOkExists(prefix + "username_template"); ok {
		data["username_template"] = v.(int)
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
	if v, ok := d.GetOk(prefix + "password"); ok {
		data["password"] = v.(string)
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

func setDatabaseConnectionDataWithUserPass(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	setDatabaseConnectionData(d, prefix, data)
	if v, ok := d.GetOk(prefix + "username"); ok {
		data["username"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "password"); ok {
		data["password"] = v.(string)
	}
}

func databaseSecretBackendConnectionCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := databaseSecretBackendConnectionPath(backend, name)

	data, err := getDatabaseAPIData(d)
	if err != nil {
		return err
	}

	if v, ok := d.GetOkExists("verify_connection"); ok {
		data["verify_connection"] = v.(bool)
	}

	if v, ok := d.GetOkExists("allowed_roles"); ok {
		var roles []string
		for _, role := range v.([]interface{}) {
			roles = append(roles, role.(string))
		}
		data["allowed_roles"] = strings.Join(roles, ",")
	}

	if v, ok := d.GetOkExists("root_rotation_statements"); ok {
		data["root_rotation_statements"] = v
	}

	if m, ok := d.GetOkExists("data"); ok {
		for k, v := range m.(map[string]interface{}) {
			data[k] = v.(string)
		}
	}

	log.Printf("[DEBUG] Writing connection config to %q", path)
	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error configuring database connection %q: %s", path, err)
	}

	d.SetId(path)
	log.Printf("[DEBUG] Wrote database connection config %q", path)

	return databaseSecretBackendConnectionRead(d, meta)
}

func databaseSecretBackendConnectionRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	db, err := getDBEngine(d)
	if err != nil {
		return err
	}

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

	switch db {
	case dbEngineCassandra:
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
					return fmt.Errorf("unexpected non-number %q returned as port from Vault: %s", v, err)
				}
				result["port"] = port
			}
			if v, ok := data["username"]; ok {
				result["username"] = v.(string)
			}
			if v, ok := data["password"]; ok {
				result["password"] = v.(string)
			} else if v, ok := d.GetOk("cassandra.0.password"); ok {
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
			} else if v, ok := d.GetOk("cassandra.0.pem_bundle"); ok {
				result["pem_bundle"] = v.(string)
			}
			if v, ok := data["pem_json"]; ok {
				result["pem_json"] = v.(string)
			} else if v, ok := d.GetOk("cassandra.0.pem_json"); ok {
				result["pem_json"] = v.(string)
			}
			if v, ok := data["protocol_version"]; ok {
				protocol, err := v.(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("unexpected non-number %q returned as protocol_version from Vault: %s", v, err)
				}
				result["protocol_version"] = int64(protocol)
			}
			if v, ok := data["connect_timeout"]; ok {
				timeout, err := v.(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("unexpected non-number %q returned as connect_timeout from Vault: %s", v, err)
				}
				result["connect_timeout"] = timeout
			}
			d.Set("cassandra", []map[string]interface{}{result})
		}
	case dbEngineCouchbase:
		d.Set("couchbase", getCouchbaseConnectionDetailsFromResponse(d, "couchbase.0.", resp))
	case dbEngineInfluxDB:
		d.Set("influxdb", getInfluxDBConnectionDetailsFromResponse(d, "influxdb.0.", resp))
	case dbEngineHana:
		d.Set("hana", getConnectionDetailsFromResponse(d, "hana.0.", resp))
	case dbEngineMongoDB:
		d.Set("mongodb", getConnectionDetailsFromResponse(d, "mongodb.0.", resp))
	case dbEngineMongoDBAtlas:
		details := resp.Data["connection_details"]
		data, ok := details.(map[string]interface{})
		if ok {
			result := map[string]interface{}{}

			if v, ok := data["public_key"]; ok {
				result["public_key"] = v.(string)
			}
			if v, ok := data["private_key"]; ok {
				result["private_key"] = v.(string)
			}
			if v, ok := data["project_id"]; ok {
				result["project_id"] = v.(string)
			}
			d.Set("mongodbatlas", []map[string]interface{}{result})
		}
	case dbEngineMSSQL:
		var values []map[string]interface{}
		if values, err = getMSSQLConnectionDetailsFromResponse(d, "mssql.0.", resp); err == nil {
			// err is returned outside of the switch case
			d.Set("mssql", values)
		}
	case dbEngineMySQL:
		d.Set("mysql", getMySQLConnectionDetailsFromResponse(d, "mysql.0.", resp))
	case dbEngineMySQLRDS:
		d.Set("mysql_rds", getConnectionDetailsFromResponse(d, "mysql_rds.0.", resp))
	case dbEngineMySQLAurora:
		d.Set("mysql_aurora", getConnectionDetailsFromResponse(d, "mysql_aurora.0.", resp))
	case dbEngineMySQLLegacy:
		d.Set("mysql_legacy", getConnectionDetailsFromResponse(d, "mysql_legacy.0.", resp))
	case dbEngineOracle:
		d.Set("oracle", getConnectionDetailsFromResponse(d, "oracle.0.", resp))
	case dbEnginePostgres:
		d.Set("postgresql", getConnectionDetailsFromResponse(d, "postgresql.0.", resp))
	case dbEngineElasticSearch:
		d.Set("elasticsearch", getElasticsearchConnectionDetailsFromResponse(d, "elasticsearch.0.", resp))
	case dbEngineSnowflake:
		d.Set("snowflake", getSnowflakeConnectionDetailsFromResponse(d, "snowflake.0.", resp))
	case dbEngineRedshift:
		d.Set("redshift", getConnectionDetailsFromResponse(d, "redshift.0.", resp))
	default:
		return fmt.Errorf("no response handler for dbEngine: %s", db)
	}

	if err != nil {
		return fmt.Errorf("error reading response for %q: %w", path, err)
	}

	var roles []string
	for _, role := range resp.Data["allowed_roles"].([]interface{}) {
		roles = append(roles, role.(string))
	}

	if err := d.Set("allowed_roles", roles); err != nil {
		return err
	}

	if err := d.Set("backend", backend); err != nil {
		return err
	}

	if err := d.Set("name", name); err != nil {
		return err
	}

	if err := d.Set("root_rotation_statements", resp.Data["root_credentials_rotate_statements"]); err != nil {
		return err
	}

	if v, ok := resp.Data["verify_connection"]; ok {
		if err := d.Set("verify_connection", v.(bool)); err != nil {
			return err
		}
	}

	if err := d.Set("plugin_name", resp.Data["plugin_name"]); err != nil {
		return err
	}

	return nil
}

func databaseSecretBackendConnectionUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := databaseSecretBackendConnectionPath(backend, name)

	data, err := getDatabaseAPIData(d)
	if err != nil {
		return err
	}

	if v, ok := d.GetOkExists("verify_connection"); ok {
		data["verify_connection"] = v.(bool)
	}

	if v, ok := d.GetOkExists("allowed_roles"); ok {
		var roles []string
		for _, role := range v.([]interface{}) {
			roles = append(roles, role.(string))
		}
		data["allowed_roles"] = strings.Join(roles, ",")
	}

	if v, ok := d.GetOkExists("root_rotation_statements"); ok {
		data["root_rotation_statements"] = v
	}

	if m, ok := d.GetOkExists("data"); ok {
		for k, v := range m.(map[string]interface{}) {
			// Vault does not return the password in the API. If the root credentials have been rotated, sending
			// the old password in the update request would break the connection config. Thus we only send it,
			// if it actually changed, to still support updating it for non-rotated cases.
			if k == "password" && d.HasChange(k) {
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

	return databaseSecretBackendConnectionRead(d, meta)
}

func databaseSecretBackendConnectionDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
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
	client := meta.(*api.Client)

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
