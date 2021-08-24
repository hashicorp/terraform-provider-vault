package util

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/terraform-plugin-sdk/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
	awsauth "github.com/hashicorp/vault/builtin/credential/aws"
	"github.com/hashicorp/vault/command/config"
)

type Client struct {
	*api.Client
	Data  *schema.ResourceData
	mutex sync.Mutex
}

// Auth wrap the lazy init error with Auth.
type Auth struct {
	*api.Auth
	err error
}

// Logical wrap the lazy init error with Logical.
type Logical struct {
	*api.Logical
	err error
}

// TokenAuth wraps the lazy init error with TokenAuth.
type TokenAuth struct {
	*api.TokenAuth
	err error
}

// Sys wraps the lazy init error with Sys.
type Sys struct {
	*api.Sys
	err error
}

func (c *Client) lazyInit() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// client has already be initialized.
	if c.Client != nil {
		return nil
	}

	d := c.Data

	clientConfig := api.DefaultConfig()
	addr := d.Get("address").(string)
	if addr != "" {
		clientConfig.Address = addr
	}

	clientAuthI := d.Get("client_auth").([]interface{})
	if len(clientAuthI) > 1 {
		return fmt.Errorf("client_auth block may appear only once")
	}

	clientAuthCert := ""
	clientAuthKey := ""
	if len(clientAuthI) == 1 {
		clientAuth := clientAuthI[0].(map[string]interface{})
		clientAuthCert = clientAuth["cert_file"].(string)
		clientAuthKey = clientAuth["key_file"].(string)
	}

	err := clientConfig.ConfigureTLS(&api.TLSConfig{
		CACert:   d.Get("ca_cert_file").(string),
		CAPath:   d.Get("ca_cert_dir").(string),
		Insecure: d.Get("skip_tls_verify").(bool),

		ClientCert: clientAuthCert,
		ClientKey:  clientAuthKey,
	})
	if err != nil {
		return fmt.Errorf("failed to configure TLS for Vault API: %s", err)
	}

	clientConfig.HttpClient.Transport = logging.NewTransport("Vault", clientConfig.HttpClient.Transport)

	client, err := api.NewClient(clientConfig)
	if err != nil {
		return fmt.Errorf("failed to configure Vault API: %s", err)
	}

	client.SetCloneHeaders(true)

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

	// Try an get the token from the config or token helper
	token, err := ProviderToken(d)
	if err != nil {
		return err
	}

	// Attempt to use auth/<mount>login if 'auth_login' is provided in provider config
	authLoginI := d.Get("auth_login").([]interface{})
	if len(authLoginI) > 1 {
		return fmt.Errorf("auth_login block may appear only once")
	}

	if len(authLoginI) == 1 {
		authLogin := authLoginI[0].(map[string]interface{})
		authLoginPath := authLogin["path"].(string)
		authLoginNamespace := ""
		if authLoginNamespaceI, ok := authLogin["namespace"]; ok {
			authLoginNamespace = authLoginNamespaceI.(string)
			client.SetNamespace(authLoginNamespace)
		}
		authLoginParameters := authLogin["parameters"].(map[string]interface{})

		method := authLogin["method"].(string)
		if method == "aws" {
			if err := SignAWSLogin(authLoginParameters); err != nil {
				return fmt.Errorf("error signing AWS login request: %s", err)
			}
		}

		secret, err := client.Logical().Write(authLoginPath, authLoginParameters)
		if err != nil {
			return err
		}
		token = secret.Auth.ClientToken
	}
	if token != "" {
		client.SetToken(token)
	}
	if client.Token() == "" {
		return errors.New("no vault token found")
	}

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
	tokenInfo, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return err
	}
	if tokenNamespaceRaw, ok := tokenInfo.Data["namespace_path"]; ok {
		tokenNamespace := tokenNamespaceRaw.(string)
		if tokenNamespace != "" {
			client.SetNamespace(tokenNamespace)
		}
	}

	renewable := false
	childTokenLease, err := client.Auth().Token().Create(&api.TokenCreateRequest{
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
	client.SetToken(childToken)

	// Set the namespace to the requested namespace, if provided
	namespace := d.Get("namespace").(string)
	if namespace != "" {
		client.SetNamespace(namespace)
	}

	c.Client = client
	c.Data = nil

	return nil
}

func (c *Client) CurrentWrappingLookupFunc() (api.WrappingLookupFunc, error) {
	if err := c.lazyInit(); err != nil {
		return nil, err
	}

	return c.Client.CurrentWrappingLookupFunc(), nil
}

// Address performs the lazy initialization, then delegates.
func (c *Client) Address() (string, error) {
	if err := c.lazyInit(); err != nil {
		return "", err
	}

	return c.Client.Address(), nil
}

// Auth performs the lazy initialization, then delegates.
func (c *Client) Auth() *Auth {
	if err := c.lazyInit(); err != nil {
		return &Auth{
			err: fmt.Errorf("could not lazy init provider: %w", err),
		}
	}

	return &Auth{
		Auth: c.Client.Auth(),
	}
}

// Clone creates a same object, but a copy.
func (c *Client) Clone() (*Client, error) {
	clone := &Client{
		Data: c.Data,
	}

	var err error
	if c.Client != nil {
		clone.Client, err = c.Client.Clone()
	}

	return clone, err
}

// Logical performs the lazy initialization, then delegates.
func (c *Client) Logical() *Logical {
	if err := c.lazyInit(); err != nil {
		return &Logical{
			err: fmt.Errorf("could not lazy init provider: %w", err),
		}
	}

	return &Logical{
		Logical: c.Client.Logical(),
	}
}

func (c *Client) NewRequest(method, requestPath string) (*api.Request, error) {
	if err := c.lazyInit(); err != nil {
		return nil, err
	}

	return c.Client.NewRequest(method, requestPath), nil
}

func (c *Client) SetToken(token string) {
	if err := c.lazyInit; err != nil {
		log.Printf("[DEBUG] could not init the client during SetToken, will fail later")
		return
	}

	c.Client.SetToken(token)
}

func (c *Client) SetWrappingLookupFunc(lookupfunc api.WrappingLookupFunc) {
	if err := c.lazyInit; err != nil {
		log.Printf("[DEBUG] could not init the client during SetWrappingLookupFunc, will fail later")
		return
	}

	c.Client.SetWrappingLookupFunc(lookupfunc)
}

// Sys performs the lazy initialization, then delegates.
func (c *Client) Sys() *Sys {
	if err := c.lazyInit(); err != nil {
		return &Sys{
			err: fmt.Errorf("could not lazy init provider: %w", err),
		}
	}

	return &Sys{
		Sys: c.Client.Sys(),
	}
}

func ProviderToken(d *schema.ResourceData) (string, error) {
	if token := d.Get("token").(string); token != "" {
		return token, nil
	}

	if addAddr := d.Get("add_address_to_env").(string); addAddr == "true" {
		if addr := d.Get("address").(string); addr != "" {
			if current, exists := os.LookupEnv("VAULT_ADDR"); exists {
				defer func() {
					os.Setenv("VAULT_ADDR", current)
				}()
			} else {
				defer func() {
					os.Unsetenv("VAULT_ADDR")
				}()
			}
			os.Setenv("VAULT_ADDR", addr)
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

func SignAWSLogin(parameters map[string]interface{}) error {
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

	creds, err := awsauth.RetrieveCreds(accessKey, secretKey, securityToken)
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

	loginData, err := awsauth.GenerateLoginData(creds, headerValue, stsRegion)
	if err != nil {
		return fmt.Errorf("failed to generate AWS login data: %s", err)
	}

	parameters["iam_http_request_method"] = loginData["iam_http_request_method"]
	parameters["iam_request_url"] = loginData["iam_request_url"]
	parameters["iam_request_headers"] = loginData["iam_request_headers"]
	parameters["iam_request_body"] = loginData["iam_request_body"]

	return nil
}

func (a *Auth) Token() *TokenAuth {
	if a.err != nil {
		return &TokenAuth{
			nil,
			a.err,
		}
	}

	return &TokenAuth{
		a.Auth.Token(),
		nil,
	}
}

func (l *Logical) Delete(path string) (*api.Secret, error) {
	if l.err != nil {
		return nil, fmt.Errorf("delete failure: %w", l.err)
	}

	return l.Logical.Delete(path)
}

func (l *Logical) List(path string) (*api.Secret, error) {
	if l.err != nil {
		return nil, fmt.Errorf("list failure: %w", l.err)
	}

	return l.Logical.List(path)
}

func (l *Logical) Read(path string) (*api.Secret, error) {
	if l.err != nil {
		return nil, fmt.Errorf("read failure: %w", l.err)
	}

	return l.Logical.Read(path)
}

func (l *Logical) ReadWithData(path string, data map[string][]string) (*api.Secret, error) {
	if l.err != nil {
		return nil, fmt.Errorf("read failure: %w", l.err)
	}

	return l.Logical.ReadWithData(path, data)
}

func (l *Logical) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	if l.err != nil {
		return nil, fmt.Errorf("write failure: %w", l.err)
	}

	return l.Logical.Write(path, data)
}

func (t *TokenAuth) Create(opts *api.TokenCreateRequest) (*api.Secret, error) {
	if t.err != nil {
		return nil, fmt.Errorf("create failure: %w", t.err)
	}

	return t.TokenAuth.Create(opts)
}

func (t *TokenAuth) CreateWithRole(opts *api.TokenCreateRequest, roleName string) (*api.Secret, error) {
	if t.err != nil {
		return nil, fmt.Errorf("create failure: %w", t.err)
	}

	return t.TokenAuth.CreateWithRole(opts, roleName)
}

func (t *TokenAuth) LookupAccessor(accessor string) (*api.Secret, error) {
	if t.err != nil {
		return nil, fmt.Errorf("lookup failure: %w", t.err)
	}

	return t.TokenAuth.LookupAccessor(accessor)
}

func (t *TokenAuth) LookupSelf() (*api.Secret, error) {
	if t.err != nil {
		return nil, fmt.Errorf("lookup failure: %w", t.err)
	}

	return t.TokenAuth.LookupSelf()
}

func (t *TokenAuth) Renew(token string, increment int) (*api.Secret, error) {
	if t.err != nil {
		return nil, fmt.Errorf("renew failure: %w", t.err)
	}

	return t.TokenAuth.Renew(token, increment)
}

func (t *TokenAuth) RevokeAccessor(accessor string) error {
	if t.err != nil {
		return fmt.Errorf("revoke accessor failure: %w", t.err)
	}

	return t.TokenAuth.RevokeAccessor(accessor)
}

func (s *Sys) EnableAuditWithOptions(path string, options *api.EnableAuditOptions) error {
	if s.err != nil {
		return fmt.Errorf("enable audit failure: %w", s.err)
	}

	return s.Sys.EnableAuditWithOptions(path, options)
}

func (s *Sys) EnableAuthWithOptions(path string, options *api.EnableAuthOptions) error {
	if s.err != nil {
		return fmt.Errorf("enable auth failure: %w", s.err)
	}

	return s.Sys.EnableAuthWithOptions(path, options)
}

func (s *Sys) GetPolicy(name string) (string, error) {
	if s.err != nil {
		return "", fmt.Errorf("get policy failure: %w", s.err)
	}

	return s.Sys.GetPolicy(name)
}

func (s *Sys) ListAuth() (map[string]*api.AuthMount, error) {
	if s.err != nil {
		return nil, fmt.Errorf("list auth failure: %w", s.err)
	}

	return s.Sys.ListAuth()
}

func (s *Sys) ListMounts() (map[string]*api.MountOutput, error) {
	if s.err != nil {
		return nil, fmt.Errorf("list mounts failure: %w", s.err)
	}

	return s.Sys.ListMounts()
}

func (s *Sys) Mount(path string, mountInfo *api.MountInput) error {
	if s.err != nil {
		return fmt.Errorf("mount failure: %w", s.err)
	}

	return s.Sys.Mount(path, mountInfo)
}

func (s *Sys) MountConfig(path string) (*api.MountConfigOutput, error) {
	if s.err != nil {
		return nil, fmt.Errorf("mount failure: %w", s.err)
	}

	return s.Sys.MountConfig(path)
}
func (s *Sys) TuneMount(path string, config api.MountConfigInput) error {
	if s.err != nil {
		return fmt.Errorf("tune mount failure: %w", s.err)
	}

	return s.Sys.TuneMount(path, config)
}

func (s *Sys) Unmount(path string) error {
	if s.err != nil {
		return fmt.Errorf("unmount failure: %w", s.err)
	}

	return s.Sys.Unmount(path)
}
