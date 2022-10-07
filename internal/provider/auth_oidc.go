package provider

import (
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	jwtauth "github.com/hashicorp/vault-plugin-auth-jwt"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	// OIDC auth login fields
	// TODO: these fields should be exported from vault-plugin-auth-jwt instead
	fieldCallbackHost   = "callbackhost"
	fieldCallbackMethod = "callbackmethod"
	fieldListenAddress  = "listenaddress"
	fieldPort           = "port"
	fieldCallbackPort   = "callbackport"
	fieldSkipBrowser    = "skip_browser"
)

// GetOIDCLoginSchema for the oidc authentication engine.
func GetOIDCLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the oidc method",
		GetOIDCLoginSchemaResource,
	)
}

// GetOIDCLoginSchemaResource for the oidc authentication engine.
func GetOIDCLoginSchemaResource(_ string) *schema.Resource {
	s := mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the login role.",
			},
			consts.FieldCallbackListenerAddress: {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "The callback listener's address. Must be a valid URI without the path.",
				ValidateDiagFunc: GetValidateDiagURI([]string{"tcp"}),
			},
			consts.FieldCallbackAddress: {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "The callback address. Must be a valid URI without the path.",
				ValidateDiagFunc: GetValidateDiagURI([]string{"http", "https"}),
			},
		},
	}, consts.MountTypeOIDC)

	return s
}

// AuthLoginOIDC provides an interface for authenticating to the
// oidc authentication engine.
// Requires configuration provided by SchemaLoginOIDC.
type AuthLoginOIDC struct {
	AuthLoginCommon
}

// MountPath for the cert authentication engine.
func (l *AuthLoginOIDC) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the oidc authentication engine.
// OIDC does not require a login path, so in this case it will always be empty.
func (l *AuthLoginOIDC) LoginPath() string {
	return ""
}

func (l *AuthLoginOIDC) Init(d *schema.ResourceData, authField string) error {
	if err := l.AuthLoginCommon.Init(d, authField); err != nil {
		return err
	}

	if err := l.checkRequiredFields(d, consts.FieldRole); err != nil {
		return err
	}

	return nil
}

// Method name for the oidc authentication engine.
func (l *AuthLoginOIDC) Method() string {
	return consts.AuthMethodOIDC
}

// Login using the oidc authentication engine.
func (l *AuthLoginOIDC) Login(client *api.Client) (*api.Secret, error) {
	if !l.initialized {
		return nil, fmt.Errorf("auth login not initiailized")
	}

	params, err := l.getAuthParams()
	if err != nil {
		return nil, err
	}

	handler := &jwtauth.CLIHandler{}
	return handler.Auth(client, params)
}

func (l *AuthLoginOIDC) getAuthParams() (map[string]string, error) {
	var role string
	// TODO: add common getParam() to AuthLoginCommon
	if v, ok := l.params[consts.FieldRole]; ok {
		role = v.(string)
	} else {
		return nil, fmt.Errorf("%q is not set", consts.FieldRole)
	}

	params := map[string]string{
		consts.FieldMount: l.MountPath(),
		consts.FieldRole:  role,
		fieldSkipBrowser:  "true",
	}

	parseURL := func(param string) (*url.URL, error) {
		if v, ok := l.params[param]; ok {
			addr := v.(string)
			if addr != "" {
				return url.Parse(addr)
			}
		}
		return nil, nil
	}

	if u, err := parseURL(consts.FieldCallbackListenerAddress); err != nil {
		return nil, err
	} else if u != nil {
		params[fieldListenAddress] = u.Hostname()
		params[fieldPort] = u.Port()
	}

	if u, err := parseURL(consts.FieldCallbackAddress); err != nil {
		return nil, err
	} else if u != nil {
		params[fieldCallbackHost] = u.Hostname()
		params[fieldCallbackPort] = u.Port()
		params[fieldCallbackMethod] = u.Scheme
	}

	return params, nil
}
