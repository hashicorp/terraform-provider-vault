// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const defaultAzureScope = "https://management.azure.com//.default"

func init() {
	field := consts.FieldAuthLoginAzure
	if err := globalAuthLoginRegistry.Register(field,
		func(r *schema.ResourceData) (AuthLogin, error) {
			a := &AuthLoginAzure{}
			return a.Init(r, field)
		}, GetAzureLoginSchema); err != nil {
		panic(err)
	}
}

// GetAzureLoginSchema for the azure authentication engine.
func GetAzureLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the azure method",
		GetAzureLoginSchemaResource,
	)
}

// GetAzureLoginSchemaResource for the azure authentication engine.
func GetAzureLoginSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldJWT: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "A signed JSON Web Token. If not specified on will be " +
					"created automatically",
				DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarAzureAuthJWT, nil),
			},
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the login role.",
			},
			consts.FieldVMName: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The virtual machine name for the machine that generated the MSI token. " +
					"This information can be obtained through instance metadata.",
			},
			consts.FieldVMSSName: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The virtual machine scale set name for the machine that generated " +
					"the MSI token. This information can be obtained through instance metadata.",
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldVMName)},
			},
			consts.FieldTenantID: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Provides the tenant ID to use in a multi-tenant " +
					"authentication scenario.",
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldJWT)},
			},
			consts.FieldScope: {
				Type:          schema.TypeString,
				Optional:      true,
				Default:       defaultAzureScope,
				Description:   "The scopes to include in the token request.",
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldJWT)},
			},
		},
	}, authField, consts.MountTypeAzure)
}

var _ AuthLogin = (*AuthLoginAzure)(nil)

type AuthLoginAzure struct {
	AuthLoginCommon
}

// MountPath for the azure authentication engine.
func (l *AuthLoginAzure) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the azure authentication engine.
func (l *AuthLoginAzure) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

func (l *AuthLoginAzure) Init(d *schema.ResourceData, authField string) (AuthLogin, error) {
	if err := l.AuthLoginCommon.Init(d, authField,
		func(data *schema.ResourceData) error {
			err := l.checkRequiredFields(d, l.requiredParams()...)
			if err != nil {
				return err
			}
			return l.checkFieldsOneOf(d, consts.FieldVMName, consts.FieldVMSSName)
		},
	); err != nil {
		return nil, err
	}

	return l, nil
}

func (l *AuthLoginAzure) requiredParams() []string {
	return []string{consts.FieldRole}
}

// Method name for the azure authentication engine.
func (l *AuthLoginAzure) Method() string {
	return consts.AuthMethodAzure
}

// Login using the azure authentication engine.
func (l *AuthLoginAzure) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	params, err := l.copyParams(l.requiredParams()...)
	if err != nil {
		return nil, err
	}

	if v, ok := l.params[consts.FieldVMName]; ok {
		params[consts.FieldVMName] = v
	} else if v, ok := l.params[consts.FieldVMName]; ok {
		params[consts.FieldVMSSName] = v
	}

	ctx := context.Background()
	jwt, err := l.getJWT(ctx)
	if err != nil {
		return nil, err
	}

	params[consts.FieldJWT] = jwt
	return l.login(client, l.LoginPath(), params)
}

func (l *AuthLoginAzure) getJWT(ctx context.Context) (string, error) {
	if jwt, ok := l.params[consts.FieldJWT].(string); ok && jwt != "" {
		return jwt, nil
	}

	// Initialize DefaultAzureCredential
	creds, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", err
	}

	var scopes []string
	if v, ok := l.params[consts.FieldScope].(string); ok {
		scopes = append(scopes, v)
	}

	tOpts := policy.TokenRequestOptions{
		Scopes: scopes,
	}
	if v, ok := l.params[consts.FieldTenantID]; ok {
		tOpts.TenantID = v.(string)
	}

	token, err := creds.GetToken(ctx, tOpts)
	if err != nil {
		return "", err
	}

	return token.Token, nil
}
