package vault

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/vault/consts"
)

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

	err := clientConfig.ConfigureTLS(&api.TLSConfig{
		CACert:   d.Get("ca_cert_file").(string),
		CAPath:   d.Get("ca_cert_dir").(string),
		Insecure: d.Get("skip_tls_verify").(bool),

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

	maxHTTPRetriesCCC = d.Get("max_retries_ccc").(int)

	// Try an get the token from the config or token helper
	token, err := providerToken(d)
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
// namespace. The value for the namespace is resolved from schema.ResourceData,
// or terraform.InstanceState.
func GetClient(i interface{}, meta interface{}) (*api.Client, error) {
	p, ok := meta.(*ProviderMeta)
	if !ok {
		return nil, fmt.Errorf("meta argument must be a ProviderMeta")
	}

	var ns string
	switch v := i.(type) {
	case *schema.ResourceData:
		if v, ok := v.GetOk(consts.FieldNamespace); ok {
			ns = v.(string)
		}
	case *terraform.InstanceState:
		ns = v.Attributes[consts.FieldNamespace]
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}

	if ns != "" {
		return p.GetNSClient(ns)
	}

	return p.GetClient(), nil
}
