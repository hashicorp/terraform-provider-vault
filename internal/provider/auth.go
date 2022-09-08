package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var AuthLoginFields = []string{
	consts.FieldAuthLoginDefault,
	consts.FieldAuthLoginUserpass,
	consts.FieldAuthLoginAWS,
}

type AuthLogin interface {
	Init(data *schema.ResourceData, authFiled string) error
	Schema() *schema.Resource
	LoginPath() string
	MountPath() string
	Method() string
	Login(client *api.Client) (*api.Secret, error)
	Namespace() string
}

type AuthLoginCommon struct {
	authField string
	mount     string
	params    map[string]interface{}
}

func (l *AuthLoginCommon) Init(d *schema.ResourceData, authField string) error {
	l.authField = authField
	path, params, err := l.init(d)
	if err != nil {
		return err
	}

	l.mount = path
	l.params = params

	return nil
}

func (l *AuthLoginCommon) Namespace() string {
	if l.params != nil {
		ns, ok := l.params[consts.FieldNamespace].(string)
		if ok {
			return ns
		}
	}
	return ""
}

func (l *AuthLoginCommon) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

func (l *AuthLoginCommon) Method() string {
	return ""
}

func (l *AuthLoginCommon) copyParams() map[string]interface{} {
	params := make(map[string]interface{}, len(l.params))
	for k, v := range l.params {
		params[k] = v
	}
	return params
}

func (l *AuthLoginCommon) login(client *api.Client, path string, params map[string]interface{}) (*api.Secret, error) {
	return client.Logical().Write(path, params)
}

func (l *AuthLoginCommon) init(d *schema.ResourceData) (string, map[string]interface{}, error) {
	v, ok := d.GetOk(l.authField)
	if !ok {
		return "", nil, fmt.Errorf("resource data missing %q", l.authField)
	}

	config := v.([]interface{})
	if len(config) != 1 {
		// this should never happen
		return "", nil, fmt.Errorf("empty config for %q", l.authField)
	}

	var path string
	if v, ok := l.getOk(d, consts.FieldPath); ok {
		path = v.(string)
	} else if v, ok := l.getOk(d, consts.FieldMount); ok {
		path = v.(string)
	} else {
		return "", nil, fmt.Errorf("no valid path configured in %#v", d)
	}

	var params map[string]interface{}
	if v, ok := l.getOk(d, consts.FieldParameters); ok {
		params = v.(map[string]interface{})
	} else {
		params = config[0].(map[string]interface{})
	}

	return path, params, nil
}

func (l *AuthLoginCommon) getOk(d *schema.ResourceData, field string) (interface{}, bool) {
	return d.GetOk(fmt.Sprintf("%s.0.%s", l.authField, field))
}

func GetAuthLogin(r *schema.ResourceData) (AuthLogin, error) {
	for _, authField := range AuthLoginFields {
		_, ok := r.GetOk(authField)
		if !ok {
			continue
		}

		var l AuthLogin
		switch authField {
		case consts.FieldAuthLoginDefault:
			l = &AuthLoginGeneric{}
		case consts.FieldAuthLoginAWS:
			l = &AuthLoginAWS{}
		case consts.FieldAuthLoginUserpass:
			l = &AuthLoginUserpass{}
		default:
			return nil, nil
		}

		if err := l.Init(r, authField); err != nil {
			return nil, err
		}

		return l, nil
	}

	return nil, nil
}

func mustAddLoginSchema(r *schema.Resource) *schema.Resource {
	MustAddSchema(r, map[string]*schema.Schema{
		consts.FieldNamespace: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldMount: {
			Type:     schema.TypeString,
			Optional: true,
			Default:  consts.AuthMethodUserpass,
		},
	})

	return r
}
