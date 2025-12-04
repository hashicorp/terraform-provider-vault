// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func init() {
	field := consts.FieldAuthLoginRadius
	if err := globalAuthLoginRegistry.Register(field,
		func(r *schema.ResourceData) (AuthLogin, error) {
			a := &AuthLoginRadius{}
			return a.Init(r, field)
		}, GetRadiusLoginSchema); err != nil {
		panic(err)
	}
}

// GetRadiusLoginSchema for the radius authentication engine.
func GetRadiusLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the radius method",
		GetRadiusLoginSchemaResource,
	)
}

// GetRadiusLoginSchemaResource for the radius authentication engine.
func GetRadiusLoginSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldUsername: {
				Type:        schema.TypeString,
				Description: "The Radius username.",
				// can be set via an env var
				Optional: true,
			},
			consts.FieldPassword: {
				Type: schema.TypeString,
				// can be set via an env var
				Optional:    true,
				Description: "The Radius password for username.",
			},
		},
	}, authField, consts.MountTypeRadius)
}

var _ AuthLogin = (*AuthLoginRadius)(nil)

type AuthLoginRadius struct {
	AuthLoginCommon
}

// MountPath for the radius authentication engine.
func (l *AuthLoginRadius) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the radius authentication engine.
func (l *AuthLoginRadius) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

func (l *AuthLoginRadius) Init(d *schema.ResourceData, authField string) (AuthLogin, error) {
	defaults := authDefaults{
		{
			field:      consts.FieldUsername,
			envVars:    []string{consts.EnvVarRadiusUsername},
			defaultVal: "",
		},
		{
			field:      consts.FieldPassword,
			envVars:    []string{consts.EnvVarRadiusPassword},
			defaultVal: "",
		},
	}
	if err := l.AuthLoginCommon.Init(d, authField,
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.setDefaultFields(d, defaults, params)
		},
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.checkRequiredFields(d, params, consts.FieldUsername, consts.FieldPassword)
		},
	); err != nil {
		return nil, err
	}

	return l, nil
}

// Method name for the radius authentication engine.
func (l *AuthLoginRadius) Method() string {
	return consts.AuthMethodRadius
}

// Login using the radius authentication engine.
func (l *AuthLoginRadius) Login(client *api.Client) (*api.Secret, error) {
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
