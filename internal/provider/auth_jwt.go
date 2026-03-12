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
	field := consts.FieldAuthLoginJWT
	if err := globalAuthLoginRegistry.Register(field,
		func(r *schema.ResourceData) (AuthLogin, error) {
			a := &AuthLoginJWT{}
			return a.Init(r, field)
		}, GetJWTLoginSchema); err != nil {
		panic(err)
	}
}

// GetJWTLoginSchema for the jwt authentication engine.
func GetJWTLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the jwt method",
		GetJWTLoginSchemaResource,
	)
}

// GetJWTLoginSchemaResource for the jwt authentication engine.
func GetJWTLoginSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the login role.",
			},
			consts.FieldJWT: {
				Type: schema.TypeString,
				// can be set via an env var
				Optional:    true,
				Description: "A signed JSON Web Token.",
			},
		},
	}, authField, consts.MountTypeJWT)
}

var _ AuthLogin = (*AuthLoginJWT)(nil)

type AuthLoginJWT struct {
	AuthLoginCommon
}

// MountPath for the jwt authentication engine.
func (l *AuthLoginJWT) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the jwt authentication engine.
func (l *AuthLoginJWT) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

func (l *AuthLoginJWT) Init(d *schema.ResourceData, authField string) (AuthLogin, error) {
	defaults := authDefaults{
		{
			field:      consts.FieldJWT,
			envVars:    []string{consts.EnvVarVaultAuthJWT},
			defaultVal: "",
		},
	}

	if err := l.AuthLoginCommon.Init(d, authField,
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.setDefaultFields(d, defaults, params)
		},
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.checkRequiredFields(d, params, consts.FieldRole, consts.FieldJWT)
		},
	); err != nil {
		return nil, err
	}

	return l, nil
}

// Method name for the jwt authentication engine.
func (l *AuthLoginJWT) Method() string {
	return consts.AuthMethodJWT
}

// Login using the jwt authentication engine.
func (l *AuthLoginJWT) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	params, err := l.copyParamsExcluding(
		consts.FieldUseRootNamespace,
		consts.FieldNamespace,
		consts.FieldMount,
	)
	if err != nil {
		return nil, err
	}

	return l.login(client, l.LoginPath(), params)
}
