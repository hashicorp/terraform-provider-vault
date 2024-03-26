// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/config"
	"k8s.io/utils/pointer"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	DefaultMaxHTTPRetries = 2
	enterpriseMetadata    = "ent"
)

var (
	MaxHTTPRetriesCCC int

	VaultVersion110 = version.Must(version.NewSemver(consts.VaultVersion110))
	VaultVersion111 = version.Must(version.NewSemver(consts.VaultVersion111))
	VaultVersion112 = version.Must(version.NewSemver(consts.VaultVersion112))
	VaultVersion113 = version.Must(version.NewSemver(consts.VaultVersion113))
	VaultVersion114 = version.Must(version.NewSemver(consts.VaultVersion114))
	VaultVersion115 = version.Must(version.NewSemver(consts.VaultVersion115))
	VaultVersion116 = version.Must(version.NewSemver(consts.VaultVersion116))

	TokenTTLMinRecommended = time.Minute * 15
)

// ProviderMeta provides resources with access to the Vault client and
// other bits
type ProviderMeta struct {
	client       *api.Client
	resourceData *schema.ResourceData
	clientCache  map[string]*api.Client
	vaultVersion *version.Version
	mu           sync.RWMutex
}

// GetClient returns the providers default Vault client.
func (p *ProviderMeta) GetClient() (*api.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.getClient()
}

// MustGetClient returns the providers default Vault client. Panics on any error.
func (p *ProviderMeta) MustGetClient() *api.Client {
	client, err := p.GetClient()
	if err != nil {
		panic(err)
	}

	return client
}

// GetNSClient returns a namespaced Vault client.
// The provided namespace will always be set relative to the default client's
// namespace.
func (p *ProviderMeta) GetNSClient(ns string) (*api.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	client, err := p.getClient()
	if err != nil {
		return nil, err
	}

	if err := p.validate(); err != nil {
		return nil, err
	}

	ns = strings.Trim(ns, "/")
	if ns == "" {
		return nil, fmt.Errorf("empty namespace not allowed")
	}

	if root, ok := p.resourceData.GetOk(consts.FieldNamespace); ok && root.(string) != "" {
		ns = fmt.Sprintf("%s/%s", root, ns)
	}

	if p.clientCache == nil {
		p.clientCache = make(map[string]*api.Client)
	}

	if v, ok := p.clientCache[ns]; ok {
		return v, nil
	}

	c, err := client.Clone()
	if err != nil {
		return nil, err
	}

	c.SetNamespace(ns)
	p.clientCache[ns] = c

	return c, nil
}

// IsAPISupported receives a minimum version
// of type *version.Version.
//
// It returns a boolean describing whether the
// ProviderMeta vaultVersion is above the
// minimum version.
func (p *ProviderMeta) IsAPISupported(minVersion *version.Version) bool {
	ver := p.GetVaultVersion()
	if ver == nil {
		return false
	}
	return ver.GreaterThanOrEqual(minVersion)
}

// IsEnterpriseSupported returns a boolean
// describing whether the ProviderMeta
// vaultVersion supports enterprise
// features.
func (p *ProviderMeta) IsEnterpriseSupported() bool {
	ver := p.GetVaultVersion()
	if ver == nil {
		return false
	}

	return strings.Contains(ver.Metadata(), enterpriseMetadata)
}

// GetVaultVersion returns the providerMeta
// vaultVersion attribute.
func (p *ProviderMeta) GetVaultVersion() *version.Version {
	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.setVaultVersion()
	if err != nil {
		return nil
	}

	return p.vaultVersion
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

// setClient sets up an authenticated Vault client based on the
// ProviderMeta.resourceData configuration. It should typically only need to be
// called once per ProviderMeta instance. Must be called with a lock.
func (p *ProviderMeta) setClient() error {
	if p.client != nil {
		return nil
	}

	if p.resourceData == nil {
		return fmt.Errorf("nil ResourceData provided")
	}

	d := p.resourceData
	clientConfig := api.DefaultConfig()
	addr := d.Get(consts.FieldAddress).(string)
	if addr != "" {
		clientConfig.Address = addr
	}
	clientConfig.CloneTLSConfig = true

	tlsConfig := &api.TLSConfig{
		CACert:        d.Get(consts.FieldCACertFile).(string),
		CAPath:        d.Get(consts.FieldCACertDir).(string),
		Insecure:      d.Get(consts.FieldSkipTLSVerify).(bool),
		TLSServerName: d.Get(consts.FieldTLSServerName).(string),
	}

	if _, ok := d.GetOk(consts.FieldClientAuth); ok {
		prefix := fmt.Sprintf("%s.0.", consts.FieldClientAuth)
		if v, ok := d.GetOk(prefix + consts.FieldCertFile); ok {
			tlsConfig.ClientCert = v.(string)
		}
		if v, ok := d.GetOk(prefix + consts.FieldKeyFile); ok {
			tlsConfig.ClientKey = v.(string)
		}
	}

	err := clientConfig.ConfigureTLS(tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to configure TLS for Vault API: %s", err)
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
		return fmt.Errorf("failed to configure Vault API: %s", err)
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

	// Set the namespace to the requested namespace, if provided
	namespace := d.Get(consts.FieldNamespace).(string)

	authLogin, err := GetAuthLogin(d)
	if err != nil {
		return err
	}

	var token string
	if authLogin != nil {
		// the clone is only used to auth to Vault
		clone, err := client.Clone()
		if err != nil {
			return err
		}

		if clone.Token() != "" {
			log.Printf("[WARN] A vault token was set from the runtime environment, "+
				"clearing it for auth_login method %q", authLogin.Method())
			clone.ClearToken()
		}

		if ns, ok := authLogin.Namespace(); ok {
			// the namespace configured on the auth_login takes precedence over the provider's
			// for authentication only.
			log.Printf("[DEBUG] Setting Auth Login namespace to %q, use_root_namespace=%t", ns, ns == "")
			clone.SetNamespace(ns)
		} else if namespace != "" {
			// authenticate to the engine in the provider's namespace
			log.Printf("[DEBUG] Setting Auth Login namespace to %q from provider configuration", namespace)
			clone.SetNamespace(namespace)
		}

		secret, err := authLogin.Login(clone)
		if err != nil {
			return err
		}

		token = secret.Auth.ClientToken
	} else {
		// try and get the token from the config or token helper
		token, err = GetToken(d)
		if err != nil {
			return err
		}
	}

	if token != "" {
		client.SetToken(token)
	}

	if client.Token() == "" {
		return errors.New("no vault token set on Client")
	}

	tokenInfo, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("failed to lookup token, err=%w", err)
	}
	if tokenInfo == nil {
		return fmt.Errorf("no token information returned from self lookup")
	}

	warnMinTokenTTL(tokenInfo)

	var tokenNamespace string
	if v, ok := tokenInfo.Data[consts.FieldNamespacePath]; ok {
		tokenNamespace = strings.Trim(v.(string), "/")
	}

	if !d.Get(consts.FieldSkipChildToken).(bool) {
		// a child token is always created in the namespace of the parent token.
		token, err = createChildToken(d, client, tokenNamespace)
		if err != nil {
			return err
		}

		client.SetToken(token)
	}

	if namespace == "" && tokenNamespace != "" {
		// set the provider namespace to the token's namespace
		// this is here to ensure that do not break any configurations that are relying on the
		// token's namespace being used during resource provisioning.
		// In the future we should drop support for this behaviour.
		log.Printf("[WARN] The provider namespace should be set whenever "+
			"using namespaced auth tokens. You may want to update your provider "+
			"configuration's namespace to be %q, before executing terraform. "+
			"Future releases may not support this type of configuration.", tokenNamespace)

		namespace = tokenNamespace
		// set the namespace on the provider to ensure that all child
		// namespace paths are properly honoured.
		if v, ok := d.Get(consts.FieldSetNamespaceFromToken).(bool); ok && v {
			if err := d.Set(consts.FieldNamespace, namespace); err != nil {
				return err
			}
		}
	}

	if namespace != "" {
		// set the namespace on the parent client
		client.SetNamespace(namespace)
	}

	p.client = client
	return nil
}

func (p *ProviderMeta) setVaultVersion() error {
	if p.vaultVersion != nil {
		return nil
	}

	d := p.resourceData
	var vaultVersion *version.Version
	if v, ok := d.GetOk(consts.FieldVaultVersionOverride); ok {
		ver, err := version.NewVersion(v.(string))
		if err != nil {
			return fmt.Errorf("invalid value for %q, err=%w",
				consts.FieldVaultVersionOverride, err)
		}
		vaultVersion = ver
	} else if !d.Get(consts.FieldSkipGetVaultVersion).(bool) {
		// Set the Vault version to *ProviderMeta object
		client, err := p.getClient()
		if err != nil {
			return err
		}

		ver, err := getVaultVersion(client)
		if err != nil {
			return err
		}
		vaultVersion = ver
	}

	p.vaultVersion = vaultVersion

	return nil
}

// getClient returns the provider's default Vault client. Must be called with ProviderMeta.mu
func (p *ProviderMeta) getClient() (*api.Client, error) {
	if err := p.setClient(); err != nil {
		return nil, err
	}

	return p.client, nil
}

// NewProviderMeta sets up the Provider to service Vault requests.
// It is meant to be used as a schema.ConfigureFunc.
func NewProviderMeta(d *schema.ResourceData) (interface{}, error) {
	if d == nil {
		return nil, fmt.Errorf("nil ResourceData provided")
	}

	return &ProviderMeta{
		resourceData: d,
	}, nil
}

func warnMinTokenTTL(tokenInfo *api.Secret) {
	// tokens with "root" policies tend to have no TTL set, so there should be no
	// need to warn in this case.
	if policies, err := tokenInfo.TokenPolicies(); err == nil {
		for _, v := range policies {
			if v == "root" {
				return
			}
		}
	}

	// we can ignore the error here, any issue with the token will be handled later
	// on during resource provisioning
	if tokenTTL, err := tokenInfo.TokenTTL(); err == nil {
		if tokenTTL < TokenTTLMinRecommended {
			log.Printf("[WARN] The token TTL %s is below the minimum "+
				"recommended value of %s, this can result in unexpected Vault "+
				"provisioning failures e.g. 403 permission denied", tokenTTL, TokenTTLMinRecommended)
		}
	}
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

	return p.GetClient()
}

func GetClientDiag(i interface{}, meta interface{}) (*api.Client, diag.Diagnostics) {
	c, err := GetClient(i, meta)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	return c, nil
}

// IsAPISupported receives an interface
// and a minimum *version.Version.
//
// It returns a boolean after computing
// whether the API is supported by the
// providerMeta, which is obtained from
// the provided interface.
func IsAPISupported(meta interface{}, minVersion *version.Version) bool {
	var p *ProviderMeta
	switch v := meta.(type) {
	case *ProviderMeta:
		p = v
	default:
		panic(fmt.Sprintf("meta argument must be a %T, not %T", p, meta))
	}

	return p.IsAPISupported(minVersion)
}

// IsEnterpriseSupported confirms that
// the providerMeta API supports enterprise
// features.
func IsEnterpriseSupported(meta interface{}) bool {
	var p *ProviderMeta
	switch v := meta.(type) {
	case *ProviderMeta:
		p = v
	default:
		panic(fmt.Sprintf("meta argument must be a %T, not %T", p, meta))
	}

	return p.IsEnterpriseSupported()
}

func getVaultVersion(client *api.Client) (*version.Version, error) {
	clone, err := client.Clone()
	if err != nil {
		return nil, err
	}

	clone.ClearNamespace()
	resp, err := clone.Sys().SealStatus()
	if err != nil {
		return nil, fmt.Errorf("could not determine the Vault server version, err=%s", err)
	}

	if resp == nil {
		return nil, fmt.Errorf("expected response data, got nil response")
	}

	if resp.Version == "" {
		return nil, fmt.Errorf("key %q not found in response", consts.FieldVersion)
	}

	return version.Must(version.NewSemver(resp.Version)), nil
}

func createChildToken(d *schema.ResourceData, c *api.Client, namespace string) (string, error) {
	tokenName := d.Get("token_name").(string)
	if tokenName == "" {
		tokenName = "terraform"
	}

	// the clone is only used to auth to Vault
	clone, err := c.Clone()
	if err != nil {
		return "", err
	}

	if namespace != "" {
		log.Printf("[INFO] Creating child token, namespace=%q", namespace)
		clone.SetNamespace(namespace)
	}
	// In order to enforce our relatively-short lease TTL, we derive a
	// temporary child token that inherits all the policies of the
	// token we were given but expires after max_lease_ttl_seconds.
	//
	// The intent here is that Terraform will need to re-fetch any
	// secrets on each run, so we limit the exposure risk of secrets
	// that end up stored in the Terraform state, assuming that they are
	// credentials that Vault is able to revoke.
	//
	// Caution is still required with state files since not all secrets
	// can explicitly be revoked, and this limited scope won't apply to
	// any secrets that are *written* by Terraform to Vault.
	childTokenLease, err := clone.Auth().Token().Create(&api.TokenCreateRequest{
		DisplayName:    tokenName,
		TTL:            fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		ExplicitMaxTTL: fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		Renewable:      pointer.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create limited child token: %s", err)
	}

	childToken := childTokenLease.Auth.ClientToken
	policies := childTokenLease.Auth.Policies

	log.Printf("[INFO] Using Vault token with the following policies: %s", strings.Join(policies, ", "))

	return childToken, nil
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

func getHCLogger() hclog.Logger {
	logger := hclog.Default()
	if logging.IsDebugOrHigher() {
		logger.SetLevel(hclog.Debug)
	} else {
		logger.SetLevel(hclog.Error)
	}
	return logger
}
