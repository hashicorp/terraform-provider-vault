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

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-version"
	"golang.org/x/oauth2"

	hcpv "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-service/stable/2020-11-25/client/vault_service"
	hconfig "github.com/hashicorp/hcp-sdk-go/config"
	"github.com/hashicorp/hcp-sdk-go/httpclient"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/config"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	DefaultMaxHTTPRetries = 2
	enterpriseMetadata    = "ent"
)

var (
	MaxHTTPRetriesCCC int

	VaultVersion190 = version.Must(version.NewSemver(consts.VaultVersion190))
	VaultVersion110 = version.Must(version.NewSemver(consts.VaultVersion110))
	VaultVersion111 = version.Must(version.NewSemver(consts.VaultVersion111))
	VaultVersion112 = version.Must(version.NewSemver(consts.VaultVersion112))
)

// ProviderMeta provides resources with access to the Vault client and
// other bits
type ProviderMeta struct {
	client       *api.Client
	resourceData *schema.ResourceData
	clientCache  map[string]*api.Client
	m            sync.RWMutex
	vaultVersion *version.Version
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

func GetHCPVaultProxyAddress(d *schema.ResourceData) (string, error) {
	cfg, err := hconfig.NewHCPConfig(hconfig.FromEnv())
	if err != nil {
		return "", err
	}

	hcpClient, err := httpclient.New(httpclient.Config{HCPConfig: cfg})
	if err != nil {
		return "", err
	}

	hcpvClient := hcpv.New(hcpClient, nil)

	// Get the cluster
	getParams := hcpv.NewGetParams().
		WithClusterID(d.Get("hcp_vault_cluster").(string)).
		WithLocationOrganizationID(d.Get("hcp_organization").(string)).
		WithLocationProjectID(d.Get("hcp_project").(string))

	resp, err := hcpvClient.Get(getParams, nil)
	if err != nil {
		return "", fmt.Errorf("Failed to lookup HCP Vault cluster details: %v", err)
	}

	return resp.Payload.Cluster.DNSNames.Proxy, nil
}

type hcpAuthRoundTripper struct {
	// Source supplies the token to add to outgoing requests'
	// Authorization headers.
	Source oauth2.TokenSource

	// Base is the base RoundTripper used to make HTTP requests.
	// If nil, http.DefaultTransport is used.
	Base http.RoundTripper
}

func (a *hcpAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				req.Body.Close()
			}
		}()
	}

	if a.Source == nil {
		return nil, errors.New("oauth2: Transport's Source is nil")
	}
	token, err := a.Source.Token()
	if err != nil {
		return nil, err
	}

	req2 := cloneRequest(req) // per RoundTripper contract

	cookie := &http.Cookie{
		//Domain:  domain,
		Name:    "hcp_access_token",
		Value:   token.AccessToken,
		Expires: token.Expiry,
	}
	req2.AddCookie(cookie)

	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true
	return a.Base.RoundTrip(req2)
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}

func HCPProxyRoundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	cfg, err := hconfig.NewHCPConfig(hconfig.FromEnv())
	if err != nil {
		return nil, fmt.Errorf("failed retrieving HCP config: %v", err)
	}

	rt := &hcpAuthRoundTripper{
		Source: cfg,
		Base:   base,
	}

	return rt, nil
}

// NewProviderMeta sets up the Provider to service Vault requests.
// It is meant to be used as a schema.ConfigureFunc.
func NewProviderMeta(d *schema.ResourceData) (interface{}, error) {
	clientConfig := api.DefaultConfig()
	addr := d.Get(consts.FieldAddress).(string)
	hcpV := d.Get("hcp_vault_cluster").(string)
	if hcpV == "" && addr == "" {
		return nil, fmt.Errorf("address must be set if not connecting to an HCP Vault cluster")
	}
	if addr != "" {
		clientConfig.Address = addr
	}

	// If we are connecting to an HCP Vault cluster, retrieve the proxy adddress

	clientAuthI := d.Get(consts.FieldClientAuth).([]interface{})
	if len(clientAuthI) > 1 {
		return nil, fmt.Errorf("client_auth block may appear only once")
	}

	clientAuthCert := ""
	clientAuthKey := ""
	if len(clientAuthI) == 1 {
		clientAuth := clientAuthI[0].(map[string]interface{})
		clientAuthCert = clientAuth[consts.FieldCertFile].(string)
		clientAuthKey = clientAuth[consts.FieldKeyFile].(string)
	}

	err := clientConfig.ConfigureTLS(&api.TLSConfig{
		CACert:        d.Get(consts.FieldCACertFile).(string),
		CAPath:        d.Get(consts.FieldCACertDir).(string),
		Insecure:      d.Get(consts.FieldSkipTLSVerify).(bool),
		TLSServerName: d.Get(consts.FieldTLSServerName).(string),

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

	// Connect to the HCP Vault cluster instead
	if hcpV != "" {
		proxyAddr, err := GetHCPVaultProxyAddress(d)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve HCP Vault cluster's proxy address: %s", err)
		}

		clientConfig.Address = "https://" + proxyAddr

		rt, err := HCPProxyRoundTripper(clientConfig.HttpClient.Transport)
		if err != nil {
			return nil, fmt.Errorf("failed to create HCP Vault cluster proxy client: %s", err)
		}

		clientConfig.HttpClient.Transport = rt
	}

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

	authLogin, err := GetAuthLogin(d)
	if err != nil {
		return nil, err
	}

	if authLogin != nil {
		client.SetNamespace(authLogin.Namespace())
		secret, err := authLogin.Login(client)
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

	var vaultVersion *version.Version
	if v, ok := d.GetOk(consts.FieldVaultVersionOverride); ok {
		ver, err := version.NewVersion(v.(string))
		if err != nil {
			return nil, fmt.Errorf("invalid value for %q, err=%w",
				consts.FieldVaultVersionOverride, err)
		}
		vaultVersion = ver
	} else if !d.Get(consts.FieldSkipGetVaultVersion).(bool) {
		// Set the Vault version to *ProviderMeta object
		ver, err := getVaultVersion(client)
		if err != nil {
			return nil, err
		}
		vaultVersion = ver
	}
	// Set the namespace to the requested namespace, if provided
	namespace := d.Get(consts.FieldNamespace).(string)
	if namespace != "" {
		client.SetNamespace(namespace)
	}

	return &ProviderMeta{
		resourceData: d,
		client:       client,
		vaultVersion: vaultVersion,
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
	resp, err := client.Sys().SealStatus()
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
