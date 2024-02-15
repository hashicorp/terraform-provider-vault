// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func init() {
	field := consts.FieldAuthLoginGeneric
	if err := globalAuthLoginRegistry.Register(field,
		func(r *schema.ResourceData) (AuthLogin, error) {
			a := &AuthLoginGeneric{}
			return a.Init(r, field)
		},
		GetGenericLoginSchema); err != nil {
		panic(err)
	}
}

func GetGenericLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault with an existing auth method using auth/<mount>/login",
		GetGenericLoginSchemaResource,
	)
}

func GetGenericLoginSchemaResource(_ string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:     schema.TypeString,
				Required: true,
			},
			consts.FieldParameters: {
				Type:      schema.TypeMap,
				Optional:  true,
				Sensitive: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldMethod: {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}, consts.FieldAuthLoginGeneric, consts.MountTypeNone)
}

var _ AuthLogin = (*AuthLoginGeneric)(nil)

// AuthLoginGeneric provides a raw interface for authenticating to most
// authentication engines.
// Requires configuration provided by SchemaLoginGeneric.
type AuthLoginGeneric struct {
	AuthLoginCommon
	path   string
	method string
}

func (l *AuthLoginGeneric) Init(d *schema.ResourceData, authField string) (AuthLogin, error) {
	l.authField = authField

	path, params, err := l.init(d)
	if err != nil {
		return nil, err
	}

	l.path = path
	l.params = params

	if v, ok := l.getOk(d, consts.FieldMethod); ok {
		l.method = v.(string)
	}

	return l, nil
}

func (l *AuthLoginGeneric) LoginPath() string {
	return l.path
}

func (l *AuthLoginGeneric) Method() string {
	return l.method
}

func (l *AuthLoginGeneric) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	params, err := l.copyParamsExcluding(
		consts.FieldNamespace,
		consts.FieldUseRootNamespace,
	)
	if err != nil {
		return nil, err
	}

	switch l.Method() {
	// the AWS auth method was previously handled by the auth_login generic
	// resource.
	case consts.AuthMethodAWS:
		if err := signAWSLogin(params, getHCLogger()); err != nil {
			return nil, fmt.Errorf("error signing AWS login request: %s", err)
		}
	}

	return l.login(client, l.LoginPath(), params)
}
