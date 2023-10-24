// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/util"
)

type (
	loginSchemaFunc   func(string) *schema.Schema
	getSchemaResource func(string) *schema.Resource
	validateFunc      func(data *schema.ResourceData) error
	authLoginFunc     func(*schema.ResourceData) (AuthLogin, error)
)

// authLoginEntry is the tuple of authLoginFunc, schemaFunc.
type authLoginEntry struct {
	field      string
	loginFunc  authLoginFunc
	schemaFunc loginSchemaFunc
}

// AuthLogin returns a new AuthLogin instance from provided schema.ResourceData.
func (a *authLoginEntry) AuthLogin(r *schema.ResourceData) (AuthLogin, error) {
	return a.loginFunc(r)
}

// LoginSchema returns the AuthLogin's schema.Schema.
func (a *authLoginEntry) LoginSchema() *schema.Schema {
	return a.schemaFunc(a.Field())
}

// Field returns the entry's top level schema field name. E.g. auth_jwt.
func (a *authLoginEntry) Field() string {
	return a.field
}

// authLoginRegistry provides the storage for authLoginEntry, mapped to the
// entry's field name.
type authLoginRegistry struct {
	m sync.Map
}

// Register field for loginFunc and schemaFunc. A field can only be registered
// once.
func (r *authLoginRegistry) Register(field string, loginFunc authLoginFunc, schemaFunc loginSchemaFunc) error {
	e := &authLoginEntry{
		field:      field,
		loginFunc:  loginFunc,
		schemaFunc: schemaFunc,
	}

	_, loaded := r.m.LoadOrStore(field, e)
	if loaded {
		return fmt.Errorf("auth login field %s is already registered", field)
	}
	return nil
}

// Get the authLoginEntry for field.
func (r *authLoginRegistry) Get(field string) (*authLoginEntry, error) {
	v, ok := r.m.Load(field)
	if !ok {
		return nil, fmt.Errorf("auth login function not registered for %s", field)
	}
	if entry, ok := v.(*authLoginEntry); ok {
		return entry, nil
	} else {
		return nil, fmt.Errorf("invalid type %T store in registry", v)
	}
}

// Fields returns the names of all registered AuthLogin's
func (r *authLoginRegistry) Fields() []string {
	var keys []string
	r.m.Range(func(key, _ interface{}) bool {
		keys = append(keys, key.(string))
		return true
	})

	return keys
}

// Values returns a slice of all registered authLoginEntry(s).
func (r *authLoginRegistry) Values() []*authLoginEntry {
	var result []*authLoginEntry
	r.m.Range(func(key, value interface{}) bool {
		result = append(result, value.(*authLoginEntry))
		return true
	})

	return result
}

// AuthLoginFields supported by the provider.
var (
	authLoginInitCheckError = errors.New("auth login not initialized")

	globalAuthLoginRegistry = &authLoginRegistry{}
)

type AuthLogin interface {
	Init(*schema.ResourceData, string) (AuthLogin, error)
	MountPath() string
	LoginPath() string
	Method() string
	Login(*api.Client) (*api.Secret, error)
	Namespace() (string, bool)
	Params() map[string]interface{}
}

// AuthLoginCommon providing common methods for other AuthLogin* implementations.
type AuthLoginCommon struct {
	authField   string
	mount       string
	params      map[string]interface{}
	initialized bool
}

func (l *AuthLoginCommon) Params() map[string]interface{} {
	return l.params
}

func (l *AuthLoginCommon) Init(d *schema.ResourceData, authField string, validators ...validateFunc) error {
	l.authField = authField
	path, params, err := l.init(d)
	if err != nil {
		return err
	}

	for _, vf := range validators {
		if err := vf(d); err != nil {
			return err
		}
	}

	l.mount = path
	l.params = params

	return l.validate()
}

func (l *AuthLoginCommon) Namespace() (string, bool) {
	if l.params != nil {
		if v, ok := l.params[consts.FieldIsRootNamespace]; ok && v.(bool) {
			return "", true
		}

		if ns, ok := l.params[consts.FieldNamespace]; ok && ns.(string) != "" {
			return ns.(string), true
		}

	}
	return "", false
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
	if client.Token() != "" {
		return nil, fmt.Errorf("vault login client has a token set")
	}

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
	} else if l.mount != consts.MountTypeNone {
		return "", nil, fmt.Errorf("no valid path configured for %q", l.authField)
	}

	var params map[string]interface{}
	if v, ok := l.getOk(d, consts.FieldParameters); ok {
		params = v.(map[string]interface{})
	} else {
		v := config[0]
		if v == nil {
			params = make(map[string]interface{})
		} else {
			params = v.(map[string]interface{})
		}
	}

	if v, ok := params[consts.FieldIsRootNamespace]; ok && !v.(bool) {
		delete(params, consts.FieldIsRootNamespace)
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
	return d.GetOk(l.fieldPath(d, field))
}

func (l *AuthLoginCommon) fieldPath(d *schema.ResourceData, field string) string {
	return fmt.Sprintf("%s.0.%s", l.authField, field)
}

func (l *AuthLoginCommon) validate() error {
	if !l.initialized {
		return authLoginInitCheckError
	}

	return nil
}

func GetAuthLogin(r *schema.ResourceData) (AuthLogin, error) {
	for _, authField := range globalAuthLoginRegistry.Fields() {
		_, ok := r.GetOk(authField)
		if !ok {
			continue
		}

		entry, err := globalAuthLoginRegistry.Get(authField)
		if err != nil {
			return nil, err
		}

		return entry.AuthLogin(r)
	}

	return nil, nil
}

func mustAddLoginSchema(r *schema.Resource, defaultMount string) *schema.Resource {
	m := map[string]*schema.Schema{
		consts.FieldNamespace: {
			Type:     schema.TypeString,
			Optional: true,
			Description: fmt.Sprintf(
				"The authentication engine's namespace. Conflicts with %s",
				consts.FieldIsRootNamespace,
			),
		},
		consts.FieldIsRootNamespace: {
			Type:     schema.TypeBool,
			Optional: true,
			Description: fmt.Sprintf(
				"Authenticate to the root Vault namespace. Conflicts with %s",
				consts.FieldNamespace,
			),
			ConflictsWith: []string{consts.FieldNamespace},
		},
	}

	if defaultMount != consts.MountTypeNone {
		m[consts.FieldMount] = &schema.Schema{
			Type:             schema.TypeString,
			Optional:         true,
			Description:      "The path where the authentication engine is mounted.",
			Default:          defaultMount,
			ValidateDiagFunc: ValidateDiagPath,
		}
	}

	MustAddSchema(r, m)

	return r
}

func getLoginSchema(authField, description string, resourceFunc getSchemaResource) *schema.Schema {
	return &schema.Schema{
		Type:          schema.TypeList,
		Optional:      true,
		MaxItems:      1,
		Description:   description,
		Elem:          resourceFunc(authField),
		ConflictsWith: util.CalculateConflictsWith(authField, globalAuthLoginRegistry.Fields()),
	}
}

// MustAddAuthLoginSchema adds all supported auth login type schema.Schema to
// a schema map.
func MustAddAuthLoginSchema(s map[string]*schema.Schema) {
	for _, v := range globalAuthLoginRegistry.Values() {
		mustAddSchema(v.Field(), v.LoginSchema(), s)
	}
}
