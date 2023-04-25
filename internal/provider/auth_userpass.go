// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// GetUserpassLoginSchema for the userpass authentication engine.
func GetUserpassLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the userpass method",
		GetUserpassLoginSchemaResource,
	)
}

// GetUserpassLoginSchemaResource for the userpass authentication engine.
func GetUserpassLoginSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldUsername: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Login with username",
				DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarUsername, nil),
			},
			consts.FieldPassword: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Login with password",
				DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarPassword, nil),
			},
			consts.FieldPasswordFile: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Login with password from a file",
				DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarPasswordFile, nil),
				// unfortunately the SDK does support conflicting relative fields
				// within a list type. As long as the top level schema does not change
				// we should be good to hard code fully qualified path like so.
				ConflictsWith: []string{
					fmt.Sprintf("%s.0.%s", authField, consts.FieldPassword),
				},
			},
		},
	}, consts.MountTypeUserpass)
}

// AuthLoginUserpass provides an interface for authenticating to the
// userpass authentication engine.
// Requires configuration provided by SchemaLoginUserpass.
type AuthLoginUserpass struct {
	AuthLoginCommon
}

// LoginPath for the userpass authentication engine.
func (l *AuthLoginUserpass) LoginPath() string {
	return fmt.Sprintf("auth/%s/login/%s", l.MountPath(), l.params[consts.FieldUsername])
}

// Method name for the userpass authentication engine.
func (l *AuthLoginUserpass) Method() string {
	return consts.AuthMethodUserpass
}

// Login using the userpass authentication engine.
func (l *AuthLoginUserpass) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	params, err := l.copyParamsExcluding(
		consts.FieldNamespace,
		consts.FieldMount,
	)
	if err != nil {
		return nil, err
	}

	if err := setupUserpassAuthParams(params); err != nil {
		return nil, err
	}

	return l.login(client, l.LoginPath(), params)
}

func setupUserpassAuthParams(params map[string]interface{}) error {
	method := consts.AuthMethodUserpass

	v, ok := params[consts.FieldUsername]
	if !ok {
		return fmt.Errorf("auth method %q, %q not set in %q",
			method,
			consts.FieldUsername,
			consts.FieldParameters,
		)
	}

	username := v.(string)

	// the password can be had from various sources
	var p string
	var passwordFile string
	if v, ok := params[consts.FieldPassword]; ok && v != nil {
		p = v.(string)
	} else if v, ok := params[consts.FieldPasswordFile]; ok && v != nil {
		passwordFile = v.(string)
		delete(params, consts.FieldPasswordFile)
	}

	if v, ok := params[consts.FieldPassword]; ok && v != nil {
		p = v.(string)
	}

	if passwordFile != "" && p != "" {
		return fmt.Errorf("auth method %q, mutually exclusive auth params provided: %s",
			method,
			strings.Join([]string{consts.FieldPassword, consts.FieldPasswordFile}, ", "))
	}

	if passwordFile != "" {
		f, err := os.Open(passwordFile)
		if err != nil {
			return err
		}

		v, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		p = string(v)
	}

	params[consts.FieldPassword] = p
	params[consts.FieldUsername] = username

	return nil
}
