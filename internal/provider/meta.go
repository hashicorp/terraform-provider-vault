package provider

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/config"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var MaxHTTPRetriesCCC int

// ProviderMeta provides resources with access to the Vault client and
// other bits
type ProviderMeta struct {
	client       *api.Client
	resourceData *schema.ResourceData
	clientCache  map[string]*api.Client
	m            sync.RWMutex
}

// GetClient returns the providers default Vault client.
func (p *ProviderMeta) GetClient() *api.Client {
	return p.client
}

// GetNSClient returns a namespaced Vault client.
// The provided namespace will always be set relative to the default client's
// namespace.
func (p *ProviderMeta) GetNSClient(ns string) (*api.Client, error) {
	p.m.Lock()
	defer p.m.Unlock()

	if err := p.validate(); err != nil {
		return nil, err
	}

	if ns == "" {
		return nil, fmt.Errorf("empty namespace not allowed")
	}

	ns = strings.Trim(ns, "/")
	if root, ok := p.resourceData.GetOk(consts.FieldNamespace); ok && root.(string) != "" {
		ns = fmt.Sprintf("%s/%s", root, ns)
	}

	if p.clientCache == nil {
		p.clientCache = make(map[string]*api.Client)
	}

	if v, ok := p.clientCache[ns]; ok {
		return v, nil
	}

	c, err := p.client.Clone()
	if err != nil {
		return nil, err
	}

	c.SetNamespace(ns)
	p.clientCache[ns] = c

	return c, nil
}

func (p *ProviderMeta) validate() error {
	if p.client == nil {
		return fmt.Errorf("root api.Client not set, init with NewProviderMeta()")
	}

	if p.resourceData == nil {
		return fmt.Errorf("provider ResourceData not set, init with NewProviderMeta()")
	}

	return nil
}

// NewProviderMeta sets up the Provider to service Vault requests.
// It is meant to be used as a schema.ConfigureFunc.
func NewProviderMeta(d *schema.ResourceData) (interface{}, error) {
	clientConfig := api.DefaultConfig()
	addr := d.Get("address").(string)
	if addr != "" {
		clientConfig.Address = addr
	}

	clientAuthI := d.Get("client_auth").([]interface{})
	if len(clientAuthI) > 1 {
		return nil, fmt.Errorf("client_auth block may appear only once")
	}

	clientAuthCert := ""
	clientAuthKey := ""
	if len(clientAuthI) == 1 {
		clientAuth := clientAuthI[0].(map[string]interface{})
		clientAuthCert = clientAuth["cert_file"].(string)
		clientAuthKey = clientAuth["key_file"].(string)
	}

	caCertBytes := []byte("")
	if d.Get("ca_cert_bytes").(string) != "" {
		caCertBytes = []byte(d.Get("ca_cert_bytes").(string))
	}

	err := clientConfig.ConfigureTLS(&api.TLSConfig{
		CACert:        d.Get("ca_cert_file").(string),
		CAPath:        d.Get("ca_cert_dir").(string),
		CACertBytes:   caCertBytes,
		Insecure:      d.Get("skip_tls_verify").(bool),
		TLSServerName: d.Get("tls_server_name").(string),

		ClientCert: clientAuthCert,
		ClientKey:  clientAuthKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS for Vault API: %s", err)
	}

	clientConfig.HttpClient.Transport = helper.NewTransport(
		"Vault",
		clientConfig.HttpClient.Transport,
		helper.DefaultTransportOptions(),
	)

	// enable ReadYourWrites to support read-after-write on Vault Enterprise
	clientConfig.ReadYourWrites = true

	// set default MaxRetries
	clientConfig.MaxRetries = DefaultMaxHTTPRetries

	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure Vault API: %s", err)
	}

	// setting this is critical for proper namespace handling
	client.SetCloneHeaders(true)

	// setting this is critical for proper client cloning
	client.SetCloneToken(true)

	// Set headers if provided
	headers := d.Get("headers").([]interface{})
	parsedHeaders := client.Headers().Clone()

	if parsedHeaders == nil {
		parsedHeaders = make(http.Header)
	}

	for _, h := range headers {
		header := h.(map[string]interface{})
		if name, ok := header["name"]; ok {
			parsedHeaders.Add(name.(string), header["value"].(string))
		}
	}
	client.SetHeaders(parsedHeaders)

	client.SetMaxRetries(d.Get("max_retries").(int))

	MaxHTTPRetriesCCC = d.Get("max_retries_ccc").(int)

	// Try and get the token from the config or token helper
	token, err := GetToken(d)
	if err != nil {
		return nil, err
	}

	// Attempt to use auth/<mount>login if 'auth_login' is provided in provider config
	authLoginI := d.Get("auth_login").([]interface{})
	if len(authLoginI) > 1 {
		return "", fmt.Errorf("auth_login block may appear only once")
	}

	if len(authLoginI) == 1 {
		authLogin := authLoginI[0].(map[string]interface{})
		authLoginPath := authLogin[consts.FieldPath].(string)
		authLoginNamespace := ""
		if authLoginNamespaceI, ok := authLogin[consts.FieldNamespace]; ok {
			authLoginNamespace = authLoginNamespaceI.(string)
			client.SetNamespace(authLoginNamespace)
		}
		authLoginParameters := authLogin[consts.FieldParameters].(map[string]interface{})

		method := authLogin[consts.FieldMethod].(string)
		if method == "aws" {
			logger := hclog.Default()
			if logging.IsDebugOrHigher() {
				logger.SetLevel(hclog.Debug)
			} else {
				logger.SetLevel(hclog.Error)
			}
			if err := signAWSLogin(authLoginParameters, logger); err != nil {
				return nil, fmt.Errorf("error signing AWS login request: %s", err)
			}
		}

		secret, err := client.Logical().Write(authLoginPath, authLoginParameters)
		if err != nil {
			return nil, err
		}
		token = secret.Auth.ClientToken
	}
	if token != "" {
		client.SetToken(token)
	}
	if client.Token() == "" {
		return nil, errors.New("no vault token found")
	}

	skipChildToken := d.Get("skip_child_token").(bool)
	if !skipChildToken {
		err := setChildToken(d, client)
		if err != nil {
			return nil, err
		}
	}

	// Set the namespace to the requested namespace, if provided
	namespace := d.Get(consts.FieldNamespace).(string)
	if namespace != "" {
		client.SetNamespace(namespace)
	}

	return &ProviderMeta{
		resourceData: d,
		client:       client,
	}, nil
}

// GetClient is meant to be called from a schema.Resource function.
// It ensures that the returned api.Client's matches the resource's configured
// namespace. The value for the namespace is resolved from any of string,
// *schema.ResourceData, *schema.ResourceDiff, or *terraform.InstanceState.
func GetClient(i interface{}, meta interface{}) (*api.Client, error) {
	var p *ProviderMeta
	switch v := meta.(type) {
	case *ProviderMeta:
		p = v
	default:
		return nil, fmt.Errorf("meta argument must be a %T, not %T", p, meta)
	}

	var ns string
	switch v := i.(type) {
	case string:
		ns = v
	case *schema.ResourceData:
		if v, ok := v.GetOk(consts.FieldNamespace); ok {
			ns = v.(string)
		}
	case *schema.ResourceDiff:
		if v, ok := v.GetOk(consts.FieldNamespace); ok {
			ns = v.(string)
		}
	case *terraform.InstanceState:
		ns = v.Attributes[consts.FieldNamespace]
	default:
		return nil, fmt.Errorf("GetClient() called with unsupported type %T", v)
	}

	if ns == "" {
		// in order to import namespaced resources the user must provide
		// the namespace from an environment variable.
		ns = os.Getenv(consts.EnvVarVaultNamespaceImport)
		if ns != "" {
			log.Printf("[DEBUG] Value for %q set from environment", consts.FieldNamespace)
		}
	}

	if ns != "" {
		return p.GetNSClient(ns)
	}

	return p.GetClient(), nil
}

func setChildToken(d *schema.ResourceData, c *api.Client) error {
	tokenName := d.Get("token_name").(string)
	if tokenName == "" {
		tokenName = "terraform"
	}

	// In order to enforce our relatively-short lease TTL, we derive a
	// temporary child token that inherits all of the policies of the
	// token we were given but expires after max_lease_ttl_seconds.
	//
	// The intent here is that Terraform will need to re-fetch any
	// secrets on each run and so we limit the exposure risk of secrets
	// that end up stored in the Terraform state, assuming that they are
	// credentials that Vault is able to revoke.
	//
	// Caution is still required with state files since not all secrets
	// can explicitly be revoked, and this limited scope won't apply to
	// any secrets that are *written* by Terraform to Vault.

	// Set the namespace to the token's namespace only for the
	// child token creation
	tokenInfo, err := c.Auth().Token().LookupSelf()
	if err != nil {
		return err
	}
	if tokenNamespaceRaw, ok := tokenInfo.Data["namespace_path"]; ok {
		tokenNamespace := tokenNamespaceRaw.(string)
		if tokenNamespace != "" {
			c.SetNamespace(tokenNamespace)
		}
	}

	renewable := false
	childTokenLease, err := c.Auth().Token().Create(&api.TokenCreateRequest{
		DisplayName:    tokenName,
		TTL:            fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		ExplicitMaxTTL: fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		Renewable:      &renewable,
	})
	if err != nil {
		return fmt.Errorf("failed to create limited child token: %s", err)
	}

	childToken := childTokenLease.Auth.ClientToken
	policies := childTokenLease.Auth.Policies

	log.Printf("[INFO] Using Vault token with the following policies: %s", strings.Join(policies, ", "))

	// Set the token to the generated child token
	c.SetToken(childToken)

	return nil
}

func signAWSLogin(parameters map[string]interface{}, logger hclog.Logger) error {
	var accessKey, secretKey, securityToken string
	if val, ok := parameters["aws_access_key_id"].(string); ok {
		accessKey = val
	}

	if val, ok := parameters["aws_secret_access_key"].(string); ok {
		secretKey = val
	}

	if val, ok := parameters["aws_security_token"].(string); ok {
		securityToken = val
	}

	creds, err := awsutil.RetrieveCreds(accessKey, secretKey, securityToken, logger)
	if err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials: %s", err)
	}

	var headerValue, stsRegion string
	if val, ok := parameters["header_value"].(string); ok {
		headerValue = val
	}

	if val, ok := parameters["sts_region"].(string); ok {
		stsRegion = val
	}

	loginData, err := awsutil.GenerateLoginData(creds, headerValue, stsRegion, logger)
	if err != nil {
		return fmt.Errorf("failed to generate AWS login data: %s", err)
	}

	parameters["iam_http_request_method"] = loginData["iam_http_request_method"]
	parameters["iam_request_url"] = loginData["iam_request_url"]
	parameters["iam_request_headers"] = loginData["iam_request_headers"]
	parameters["iam_request_body"] = loginData["iam_request_body"]

	return nil
}

func GetToken(d *schema.ResourceData) (string, error) {
	if token := d.Get("token").(string); token != "" {
		return token, nil
	}

	if addAddr := d.Get("add_address_to_env").(string); addAddr == "true" {
		if addr := d.Get("address").(string); addr != "" {
			addrEnvVar := api.EnvVaultAddress
			if current, exists := os.LookupEnv(addrEnvVar); exists {
				defer func() {
					os.Setenv(addrEnvVar, current)
				}()
			} else {
				defer func() {
					os.Unsetenv(addrEnvVar)
				}()
			}
			if err := os.Setenv(addrEnvVar, addr); err != nil {
				return "", err
			}
		}
	}

	// Use ~/.vault-token, or the configured token helper.
	tokenHelper, err := config.DefaultTokenHelper()
	if err != nil {
		return "", fmt.Errorf("error getting token helper: %s", err)
	}
	token, err := tokenHelper.Get()
	if err != nil {
		return "", fmt.Errorf("error getting token: %s", err)
	}
	return strings.TrimSpace(token), nil
}

const DefaultMaxHTTPRetries = 2
