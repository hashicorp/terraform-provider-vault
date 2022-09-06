package provider

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var SchemaLoginGeneric = &schema.Resource{
	Schema: map[string]*schema.Schema{
		consts.FieldPath: {
			Type:     schema.TypeString,
			Required: true,
		},
		consts.FieldNamespace: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldParameters: {
			Type:     schema.TypeMap,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		consts.FieldMethod: {
			Type:     schema.TypeString,
			Optional: true,
		},
	},
}

// AuthLoginGeneric provides a raw interface for authenticating to most
// authentication engines.
type AuthLoginGeneric struct {
	AuthLoginCommon
	path      string
	namespace string
	method    string
}

func (l *AuthLoginGeneric) Schema() *schema.Resource {
	return nil
}

func (l *AuthLoginGeneric) Namespace() string {
	return l.namespace
}

func (l *AuthLoginGeneric) MountPath() string {
	return ""
}

func (l *AuthLoginGeneric) Init(d *schema.ResourceData, authField string) error {
	l.authField = authField

	path, params, err := l.init(d)
	if err != nil {
		return err
	}

	l.path = path
	l.params = params

	if v, ok := l.getOk(d, consts.FieldNamespace); ok {
		l.namespace = v.(string)
	}

	if v, ok := l.getOk(d, consts.FieldMethod); ok {
		l.method = v.(string)
	}

	return nil
}

func (l *AuthLoginGeneric) LoginPath() string {
	return l.path
}

func (l *AuthLoginGeneric) Method() string {
	return l.method
}

func (l *AuthLoginGeneric) Login(client *api.Client) (*api.Secret, error) {
	params := l.copyParams()

	switch l.Method() {
	// the AWS auth method was previously handled by the auth_login generic
	// resource.
	case consts.AuthMethodAWS:
		logger := hclog.Default()
		if logging.IsDebugOrHigher() {
			logger.SetLevel(hclog.Debug)
		} else {
			logger.SetLevel(hclog.Error)
		}
		if err := signAWSLogin(params, logger); err != nil {
			return nil, fmt.Errorf("error signing AWS login request: %s", err)
		}
	}

	return l.login(client, l.LoginPath(), params)
}
