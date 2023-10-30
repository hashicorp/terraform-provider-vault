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
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarRadiusUsername, nil),
			},
			consts.FieldPassword: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Radius password for username.",
				DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarRadiusPassword, nil),
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
	if err := l.AuthLoginCommon.Init(d, authField,
		func(data *schema.ResourceData) error {
			return l.checkRequiredFields(d, consts.FieldUsername, consts.FieldPassword)
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
