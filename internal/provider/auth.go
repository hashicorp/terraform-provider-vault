// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/util"
)

type (
	GetLoginSchema    func(string) *schema.Schema
	getSchemaResource func(string) *schema.Resource
)

// AuthLoginFields supported by the provider.
var (
	AuthLoginFields = []string{
		consts.FieldAuthLoginDefault,
		consts.FieldAuthLoginUserpass,
		consts.FieldAuthLoginAWS,
		consts.FieldAuthLoginCert,
		consts.FieldAuthLoginGCP,
		consts.FieldAuthLoginKerberos,
		consts.FieldAuthLoginRadius,
		consts.FieldAuthLoginOCI,
		consts.FieldAuthLoginOIDC,
		consts.FieldAuthLoginJWT,
		consts.FieldAuthLoginAzure,
	}

	authLoginInitCheckError = errors.New("auth login not initialized")
)

type AuthLogin interface {
	Init(data *schema.ResourceData, authFiled string) error
	MountPath() string
	LoginPath() string
	Method() string
	Login(client *api.Client) (*api.Secret, error)
	Namespace() string
}

// AuthLoginCommon providing common methods for other AuthLogin* implementations.
type AuthLoginCommon struct {
	authField   string
	mount       string
	params      map[string]interface{}
	initialized bool
}

func (l *AuthLoginCommon) Init(d *schema.ResourceData, authField string) error {
	l.authField = authField
	path, params, err := l.init(d)
	if err != nil {
		return err
	}

	l.mount = path
	l.params = params

	return l.validate()
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

func (l *AuthLoginCommon) copyParams(includes ...string) (map[string]interface{}, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	params := make(map[string]interface{}, len(l.params))
	if len(includes) == 0 {
		for k, v := range l.params {
			params[k] = v
		}
	} else {
		var missing []string
		for _, k := range includes {
			v, ok := l.params[k]
			if !ok {
				missing = append(missing, k)
				continue
			}
			params[k] = v
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("missing params %v", missing)
		}
	}

	return params, nil
}

func (l *AuthLoginCommon) copyParamsExcluding(excludes ...string) (map[string]interface{}, error) {
	params, err := l.copyParams()
	if err != nil {
		return nil, err
	}
	for _, k := range excludes {
		delete(params, k)
	}

	return params, nil
}

func (l *AuthLoginCommon) login(client *api.Client, path string, params map[string]interface{}) (*api.Secret, error) {
	return client.Logical().Write(path, params)
}

func (l *AuthLoginCommon) init(d *schema.ResourceData) (string, map[string]interface{}, error) {
	if l.initialized {
		return "", nil, fmt.Errorf("auth login already initialized")
	}

	v, ok := d.GetOk(l.authField)
	if !ok {
		return "", nil, fmt.Errorf("resource data missing field %q", l.authField)
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

	l.initialized = true

	return path, params, nil
}

func (l *AuthLoginCommon) checkRequiredFields(d *schema.ResourceData, required ...string) error {
	var missing []string
	for _, f := range required {
		if _, ok := l.getOk(d, f); !ok {
			missing = append(missing, f)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("required fields are unset: %v", missing)
	}

	return nil
}

func (l *AuthLoginCommon) checkFieldsOneOf(d *schema.ResourceData, fields ...string) error {
	if len(fields) == 0 {
		return nil
	}

	for _, f := range fields {
		if _, ok := l.getOk(d, f); ok {
			return nil
		}
	}

	return fmt.Errorf(
		"at least one field must be set: %v", fields)
}

func (l *AuthLoginCommon) getOk(d *schema.ResourceData, field string) (interface{}, bool) {
	return d.GetOk(fmt.Sprintf("%s.0.%s", l.authField, field))
}

func (l *AuthLoginCommon) validate() error {
	if !l.initialized {
		return authLoginInitCheckError
	}

	return nil
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
		case consts.FieldAuthLoginGCP:
			l = &AuthLoginGCP{}
		case consts.FieldAuthLoginKerberos:
			l = &AuthLoginKerberos{}
		case consts.FieldAuthLoginRadius:
			l = &AuthLoginRadius{}
		case consts.FieldAuthLoginOCI:
			l = &AuthLoginOCI{}
		case consts.FieldAuthLoginOIDC:
			l = &AuthLoginOIDC{}
		case consts.FieldAuthLoginJWT:
			l = &AuthLoginJWT{}
		case consts.FieldAuthLoginAzure:
			l = &AuthLoginAzure{}
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

func mustAddLoginSchema(r *schema.Resource, defaultMount string) *schema.Resource {
	MustAddSchema(r, map[string]*schema.Schema{
		consts.FieldNamespace: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The authentication engine's namespace.",
		},
		consts.FieldMount: {
			Type:             schema.TypeString,
			Optional:         true,
			Description:      "The path where the authentication engine is mounted.",
			Default:          defaultMount,
			ValidateDiagFunc: ValidateDiagPath,
		},
	})

	return r
}

func getLoginSchema(authField, description string, resourceFunc getSchemaResource) *schema.Schema {
	return &schema.Schema{
		Type:          schema.TypeList,
		Optional:      true,
		MaxItems:      1,
		Description:   description,
		Elem:          resourceFunc(authField),
		ConflictsWith: util.CalculateConflictsWith(authField, AuthLoginFields),
	}
}

// MustAddAuthLoginSchema adds all supported auth login type schema.Schema to
// a schema map.
func MustAddAuthLoginSchema(s map[string]*schema.Schema) {
	for _, authField := range AuthLoginFields {
		var f GetLoginSchema
		switch authField {
		case consts.FieldAuthLoginDefault:
			f = GetGenericLoginSchema
		case consts.FieldAuthLoginUserpass:
			f = GetUserpassLoginSchema
		case consts.FieldAuthLoginAWS:
			f = GetAWSLoginSchema
		case consts.FieldAuthLoginCert:
			f = GetCertLoginSchema
		case consts.FieldAuthLoginGCP:
			f = GetGCPLoginSchema
		case consts.FieldAuthLoginKerberos:
			f = GetKerberosLoginSchema
		case consts.FieldAuthLoginRadius:
			f = GetRadiusLoginSchema
		case consts.FieldAuthLoginOCI:
			f = GetOCILoginSchema
		case consts.FieldAuthLoginOIDC:
			f = GetOIDCLoginSchema
		case consts.FieldAuthLoginJWT:
			f = GetJWTLoginSchema
		case consts.FieldAuthLoginAzure:
			f = GetAzureLoginSchema
		default:
			panic(fmt.Errorf("auth login %q has no schema defined", authField))
		}

		mustAddSchema(authField, f(authField), s)
	}
}
